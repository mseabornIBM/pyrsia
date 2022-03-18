/*
   Copyright 2021 JFrog Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

use super::ArtifactManager;
use super::Hash;
use super::HashAlgorithm;

use crate::metadata_manager::metadata::Metadata;
use crate::network::kademlia_thread_safe_proxy::KademliaThreadSafeProxy;
use crate::util::env_util::*;
use anyhow::{Context, Result};
use byte_unit::Byte;
use lazy_static::lazy_static;
use libp2p::{identity, kad::record::store::MemoryStore, PeerId};
use log::{debug, error, info};
use std::fs::File;
use std::io::{BufReader, Read};
use std::panic::UnwindSafe;
use std::str;
use std::{fs, panic};
use sysinfo::{System, SystemExt, ProcessExt, NetworkExt};

//TODO: read from CLI config file
pub const ALLOCATED_SPACE_FOR_ARTIFACTS: &str = "10.84 GB";
const CPU_STRESS_CODE: i64 = 10; 
const CPU_STRESS_WEIGHT: f64 = 2_f64;
const NETWORK_STRESS_CODE: i64 = 20;
const NETWORK_STRESS_WEIGHT: f64 = 0.001_f64;
const DISK_STRESS_CODE: i64 = 30;
const DISK_STRESS_WEIGHT: f64 = 0.001_f64;

//This structure is used as the entries to the quality metrics vector
#[derive(Debug, Clone, Copy)]
struct MetricElement {
    code: i64,
    value: f64,
    weight: f64
}

lazy_static! {
    pub static ref LOCAL_KEY: identity::Keypair = identity::Keypair::generate_ed25519();
    pub static ref LOCAL_PEER_ID: PeerId = PeerId::from(LOCAL_KEY.public());
    pub static ref MEMORY_STORE: MemoryStore = MemoryStore::new(*LOCAL_PEER_ID);
    pub static ref KADEMLIA_PROXY: KademliaThreadSafeProxy = KademliaThreadSafeProxy::default();
    pub static ref ARTIFACTS_DIR: String = log_static_initialization_failure(
        "Pyrsia Artifact directory",
        Ok(read_var("PYRSIA_ARTIFACT_PATH", "pyrsia"))
    );
    pub static ref ART_MGR: ArtifactManager = {
        let dev_mode = read_var("DEV_MODE", "off");
        if dev_mode.to_lowercase() == "on" {
            log_static_initialization_failure(
                "Artifact Manager Directory",
                fs::create_dir_all(ARTIFACTS_DIR.as_str())
                    .with_context(|| "Failed to create artifact manager directory in dev mode"),
            );
        }
        log_static_initialization_failure(
            "Artifact Manager",
            ArtifactManager::new(ARTIFACTS_DIR.as_str()),
        )
    };
    pub static ref METADATA_MGR: Metadata =
        log_static_initialization_failure("Metadata Manager", Metadata::new());
}

fn log_static_initialization_failure<T: UnwindSafe>(
    label: &str,
    result: Result<T, anyhow::Error>,
) -> T {
    let panic_wrapper = panic::catch_unwind(|| match result {
        Ok(unwrapped) => unwrapped,
        Err(error) => {
            let msg = format!("Error initializing {}, error is: {}", label, error);
            error!("{}", msg);
            panic!("{}", msg)
        }
    });
    match panic_wrapper {
        Ok(normal) => normal,
        Err(partially_unwound_panic) => {
            error!("Initialization of {} panicked!", label);
            panic::resume_unwind(partially_unwound_panic)
        }
    }
}

//get_artifact: given artifact_hash(artifactName) pulls artifact for  artifact_manager and
//              returns read object to read the bytes of artifact
pub fn get_artifact(art_hash: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, anyhow::Error> {
    let hash = Hash::new(algorithm, art_hash)?;
    let result = ART_MGR.pull_artifact(&hash)?;
    let mut buf_reader: BufReader<File> = BufReader::new(result);
    let mut blob_content = Vec::new();
    buf_reader.read_to_end(&mut blob_content)?;
    Ok(blob_content)
}

//put_artifact: given artifact_hash(artifactName) & artifact_path push artifact to artifact_manager
//              and returns the boolean as true or false if it was able to create or not
pub fn put_artifact(
    artifact_hash: &[u8],
    art_reader: Box<dyn Read>,
    algorithm: HashAlgorithm,
) -> Result<bool, anyhow::Error> {
    let hash = Hash::new(algorithm, artifact_hash)?;
    info!("put_artifact hash: {}", hash);
    let mut buf_reader = BufReader::new(art_reader);
    ART_MGR
        .push_artifact(&mut buf_reader, &hash)
        .context("Error from put_artifact")
}

pub fn get_arts_count() -> Result<usize, anyhow::Error> {
    ART_MGR
        .artifacts_count()
        .context("Error while getting artifacts count")
}

pub fn get_space_available(repository_path: &str) -> Result<u64, anyhow::Error> {
    let disk_used_bytes = ART_MGR.space_used(repository_path)?;

    let mut available_space: u64 = 0;
    let total_allocated_size: u64 = Byte::from_str(ALLOCATED_SPACE_FOR_ARTIFACTS)
        .unwrap()
        .get_bytes();

    if total_allocated_size > disk_used_bytes {
        available_space = total_allocated_size - disk_used_bytes;
    }
    Ok(available_space)
}

pub fn disk_usage(repository_path: &str) -> Result<f64, anyhow::Error> {
    let disk_used_bytes = ART_MGR.space_used(repository_path)?;

    let total_allocated_size: u64 = Byte::from_str(ALLOCATED_SPACE_FOR_ARTIFACTS)
        .unwrap()
        .get_bytes();
    let mut disk_usage: f64 = 0.0;
    debug!("disk_used: {}", disk_used_bytes);
    debug!("total_allocated_size: {}", total_allocated_size);

    if total_allocated_size > disk_used_bytes {
        disk_usage = (disk_used_bytes as f64 / total_allocated_size as f64) * 100_f64;
    }
    Ok(disk_usage)
}

/***************************************************
 * Peer Quality Metrics
 ***************************************************/
// Get the local stress metric to advertise to peers
fn get_quality_metric() -> f64 {
    let qm_matrix = Vec::<MetricElement>::new();
    let sys = System::new_all();

    let (sys, qm_matrix) = get_cpu_stress(sys, qm_matrix);
    let (sys, qm_matrix)  = get_network_stress(sys, qm_matrix);
    let (_sys, qm_matrix)  = get_disk_stress(sys, qm_matrix);

    let mut qm = 0_f64;
    for metric in qm_matrix {
        qm = qm + (metric.value * metric.weight);
    }
    qm
}

// This function gets the current CPU load on the system.
fn get_cpu_stress(sys: System, mut quality_matrix: Vec::<MetricElement>) -> (System, Vec<MetricElement>) {
    let loadav =  sys.load_average();

    let cpu_stress = loadav.one; //using the average over the last 1 minute
    let metric_entry = MetricElement {
            code: CPU_STRESS_CODE,
            value: cpu_stress,
            weight: CPU_STRESS_WEIGHT
    };
    quality_matrix.push(metric_entry);
    (sys, quality_matrix)
}

//This function gets the current network load on the system
fn get_network_stress(mut sys: System, mut quality_matrix: Vec::<MetricElement>) -> (System, Vec<MetricElement>) {

    sys.refresh_networks_list();
    let networks = sys.networks();

    let mut packets_in = 0;
    let mut packets_out = 0;
    for (_interface_name, network) in networks {
        packets_in = packets_in + network.received();
        packets_out = packets_out + network.transmitted();
    }

    //TODO: add network card capabilities to the metric. cards with > network capacity should get a lower stress number.

    let metric_entry = MetricElement{
        code: NETWORK_STRESS_CODE,
        value: (packets_in as f64) + (packets_out as f64),
        weight: NETWORK_STRESS_WEIGHT
    };

    quality_matrix.push(metric_entry);
    (sys, quality_matrix)
}

fn get_disk_stress(mut sys: System, mut quality_matrix: Vec::<MetricElement>) -> (System, Vec<MetricElement>) {

    sys.refresh_all();

    // Sum up the disk usage measured as read and writes per process:
    let mut total_usage = 0_u64;
    for (_pid, process) in sys.processes() {
        let usage = process.disk_usage();
        total_usage = total_usage + usage.written_bytes + usage.read_bytes;
    }

    let metric_entry = MetricElement{
        code: DISK_STRESS_CODE,
        value: total_usage as f64,
        weight: DISK_STRESS_WEIGHT
    };

    quality_matrix.push(metric_entry);
    (sys, quality_matrix)
}

#[cfg(test)]

mod tests {
    use super::ArtifactManager;
    use super::HashAlgorithm;
    use super::*;
    use anyhow::Context;
    use assay::assay;
    use std::env;
    use std::fs::File;
    use std::path::Path;
    use std::path::PathBuf;
    use tempfile::Builder;

    use super::Hash;

    const VALID_ARTIFACT_HASH: [u8; 32] = [
        0x86, 0x5c, 0x8d, 0x98, 0x8b, 0xe4, 0x66, 0x9f, 0x3e, 0x48, 0xf7, 0x3b, 0x98, 0xf9, 0xbc,
        0x25, 0x7, 0xbe, 0x2, 0x46, 0xea, 0x35, 0xe0, 0x9, 0x8c, 0xf6, 0x5, 0x4d, 0x36, 0x44, 0xc1,
        0x4f,
    ];
    const CPU_THREADS: usize = 200;
    const NETWORK_THREADS: usize = 10;

    fn tear_down() {
        if Path::new(&env::var("PYRSIA_ARTIFACT_PATH").unwrap()).exists() {
            fs::remove_dir_all(env::var("PYRSIA_ARTIFACT_PATH").unwrap()).expect(&format!(
                "unable to remove test directory {}",
                env::var("PYRSIA_ARTIFACT_PATH").unwrap()
            ));
        }
    }

    #[assay(
        env = [
          ("PYRSIA_ARTIFACT_PATH", "pyrsia-test-node"),
          ("DEV_MODE", "on")
        ],
        teardown = tear_down()
        )]
    fn put_and_get_artifact_test() {
        debug!("put_and_get_artifact_test started !!");
        //put the artifact
        put_artifact(
            &VALID_ARTIFACT_HASH,
            Box::new(get_file_reader()?),
            HashAlgorithm::SHA256,
        )
        .context("Error from put_artifact")?;

        // pull artiafct
        let file = get_artifact(&VALID_ARTIFACT_HASH, HashAlgorithm::SHA256)
            .context("Error from get_artifact")?;

        //validate pulled artifact with the actual data
        let mut s = String::new();
        get_file_reader()?.read_to_string(&mut s)?;

        let s1 = match str::from_utf8(file.as_slice()) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        assert_eq!(s, s1);
    }

    #[test]
    fn test_that_a_metadata_manager_is_created_and_accessible() {
        let untrusted_key_pair = METADATA_MGR.untrusted_key_pair();
        assert!(!untrusted_key_pair.public_key.is_empty());
        assert!(!untrusted_key_pair.private_key.is_empty());
    }

    #[assay(
        env = [
          ("PYRSIA_ARTIFACT_PATH", "PyrisaTest"),
          ("DEV_MODE", "on")
        ]  )]
    fn test_disk_usage() {
        let tmp_dir = Builder::new().prefix("PyrisaTest").tempdir()?;
        let tmp_path = tmp_dir.path().to_owned();
        assert!(tmp_path.exists());

        let name = tmp_path.to_str().unwrap();

        let am: ArtifactManager = ArtifactManager::new(name)?;

        let usage_pct_before = disk_usage(name).context("Error from disk_usage")?;

        create_artifact(am).context("Error creating artifact")?;

        let usage_pct_after = disk_usage(name).context("Error from disk_usage")?;
        assert!(usage_pct_before < usage_pct_after);
    }

    #[assay(
        env = [
          ("PYRSIA_ARTIFACT_PATH", "PyrisaTest"),
          ("DEV_MODE", "on")
        ]  )]
    fn test_get_space_available() {
        let tmp_dir = Builder::new().prefix("PyrisaTest").tempdir()?;
        let tmp_path = tmp_dir.path().to_owned();
        assert!(tmp_path.exists());

        let name = tmp_path.to_str().unwrap();

        let am: ArtifactManager = ArtifactManager::new(name)?;
        let space_available_before =
            get_space_available(name).context("Error from get_space_available")?;

        create_artifact(am).context("Error creating artifact")?;

        let space_available_after =
            get_space_available(name).context("Error from get_space_available")?;
        assert!(space_available_after < space_available_before);
    }

    fn get_file_reader() -> Result<File, anyhow::Error> {
        // test artifact file in resources/test dir
        let mut curr_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        curr_dir.push("tests/resources/artifact_test.json");

        let path = String::from(curr_dir.to_string_lossy());
        let reader = File::open(path.as_str()).unwrap();
        Ok(reader)
    }

    fn create_artifact(am: ArtifactManager) -> Result<(), anyhow::Error> {
        let hash = Hash::new(HashAlgorithm::SHA256, &VALID_ARTIFACT_HASH)?;
        let push_result = am
            .push_artifact(&mut get_file_reader()?, &hash)
            .context("Error while pushing artifact")?;

        assert_eq!(push_result, true);
        Ok(())
    }

    #[test]
    fn cpu_load_test(){
        use sysinfo::{System, SystemExt};
        use std::thread;
        use std::time::Duration;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let qm_matrix = Vec::<MetricElement>::new();
        let mut sys = System::new_all();
        sys.refresh_all();
        let loading = Arc::new(AtomicBool::new(true));

        //first measure of CPU for benchmark
        let (_sys, qm_matrix) = get_cpu_stress(sys, qm_matrix);
        let mut qm = 0_f64;
        for metric in qm_matrix {
            qm = qm + (metric.value*metric.weight);
        }
        assert_ne!(0_f64,qm); //zero should never be returned here

        //set CPU on fire to measure stress
        let mut threads = vec![];
        for _i in 0..CPU_THREADS {
            threads.push(thread::spawn({
                let mut cpu_fire = 0;
                let loading_test = loading.clone();
                move || {
                    while loading_test.load(Ordering::Relaxed) {
                        cpu_fire = cpu_fire + 1;
                    }
                }
            }));
        }

        thread::sleep(Duration::from_millis(2200)); //let cpu spin up
        let qm2_matrix = Vec::<MetricElement>::new();
        let mut sys2 = System::new_all();
        sys2.refresh_all();

        //second measure of CPU
        let (_sys2, qm2_matrix) = get_cpu_stress(sys2, qm2_matrix);
        let mut qm2 = 0_f64;
        for metric in qm2_matrix {
            qm2 = qm2 + (metric.value*metric.weight);
        }

        assert!(qm2 >= qm);
        loading.store(false, Ordering::Relaxed);  //kill threads

        //wait for threads
        for thread in threads{
            thread.join().unwrap();
        }
        //we could add another measure of CPU did no think it was that important                   
    }

    #[test]
    fn network_load_test(){
        use sysinfo::{System, SystemExt};
        use std::net::UdpSocket;
        use std::thread;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut sys = System::new_all();
        sys.refresh_all();
        let loading = Arc::new(AtomicBool::new(true));
        let qm_matrix = Vec::<MetricElement>::new();

        //fist measure of network for benchmark
        let (_sys, qm_matrix) = get_network_stress(sys, qm_matrix);
        let mut qm = 0_f64;
        for metric in qm_matrix {
            qm = qm + (metric.value*metric.weight);
        }

        //shotgun the network with packets
        let mut threads = vec![];
        for i in 0..NETWORK_THREADS {
            threads.push(thread::spawn({
                let address: String = format_args!("127.0.0.1:3425{i}").to_string();
                let socket = UdpSocket::bind(address).expect("couldn't bind to address");
                let loading_test = loading.clone();
                move || {
                    while loading_test.load(Ordering::Relaxed) {
                        socket.send_to(&[0; 10], "127.0.0.1:4242").expect("couldn't send data");
                    }
                }
            }));
        }

        let qm2_matrix = Vec::<MetricElement>::new();
        let mut sys2 = System::new_all();
        sys2.refresh_all();

        let (_sys2, qm2_matrix) = get_network_stress(sys2, qm2_matrix);
        let mut qm2 = 0_f64;
        for metric in qm2_matrix {
            qm2 = qm2 + (metric.value*metric.weight);
        }
        assert!(qm2 > qm);
        loading.store(false, Ordering::Relaxed);  //kill threads

        //wait for threads
        for thread in threads{
            thread.join().unwrap();
        }
        //we could add another measure of network did no think it was that important  
    }

    #[test]
    fn disk_load_test(){
        use sysinfo::{System, SystemExt};
        use std::thread;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::fs;
        use std::io::Write;
        use std::fs::OpenOptions;
        use std::time::Duration;

        
        let mut sys = System::new_all();
        sys.refresh_all();
        let loading = Arc::new(AtomicBool::new(true));
        let qm_matrix = Vec::<MetricElement>::new();
        let test_file = "pyrsia_test.txt";

        // fist measure of network for benchmark
        let (_sys, qm_matrix) = get_disk_stress(sys, qm_matrix);
        let mut qm = 0_f64;
        for metric in qm_matrix {
            qm = qm + (metric.value*metric.weight);
        }

        // write some data
        let write_thread = thread::spawn({
            let file_data = "Some test data for the file!\n";
            let except_str = format!("Unable to open file {}", test_file).to_string();
            let mut f = OpenOptions::new()
                .append(true)
                .create(true)
                .open(test_file)
                .expect(&except_str);
            let loading_test = loading.clone();
            move || {
                while loading_test.load(Ordering::Relaxed) {
                    f.write_all(file_data.as_bytes()).expect("Unable to write data");
                }
                drop(f);
            }
        });

        thread::sleep(Duration::from_millis(200)); //let writes happen
        let qm2_matrix = Vec::<MetricElement>::new();
        let mut sys2 = System::new_all();
        sys2.refresh_all();

        // second measure of network
        let (_sys2, qm2_matrix) = get_disk_stress(sys2, qm2_matrix);
        let mut qm2 = 0_f64;
        for metric in qm2_matrix {
            qm2 = qm2 + (metric.value*metric.weight);
        }
        loading.store(false, Ordering::Relaxed);  //kill thread
        write_thread.join().unwrap();
        fs::remove_file(test_file).unwrap_or_else(|why|{
            assert!(false, "{:?}", why.kind());
        });
        assert!(qm2 >= qm);

        //we could add another measure of disks did no think it was that important  
    }

    #[test]
    fn quality_metric_test(){
        let quality_metric = get_quality_metric();
        assert!(quality_metric != 0_f64);
    }
}
