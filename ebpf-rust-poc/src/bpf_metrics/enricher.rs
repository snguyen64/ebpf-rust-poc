use kube::{Client, api::{Api, ListParams}};
use k8s_openapi::api::core::v1::Pod;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::fs;

#[derive(Clone, Debug)]
pub struct PodInfo {
    pub namespace: String,
    pub pod_name: String,
}

// map of <container_id, (namespace, pod_name)>
#[derive(Clone, Debug)]
pub struct PodCache {
    pub container_pod_cache: Arc<RwLock<HashMap<String, PodInfo>>>,
    pub pid_container_cache: Arc<RwLock<HashMap<u32, String>>>,
}

impl PodCache {
    pub async fn initialize() -> Self {
        let mut cache = HashMap::new();

        let client = Client::try_default().await.expect("Failed to create Kubernetes client");
        let pods: Api<Pod> = Api::all(client);
        let lp = ListParams::default();

        match pods.list(&lp).await {
            Ok(pod_list) => {
                for pod in pod_list.items {
                    if let (Some(namespace), Some(name)) = (pod.metadata.namespace.clone(), pod.metadata.name.clone()) {
                        if let Some(container_statuses) = pod.status.as_ref().and_then(|status| status.container_statuses.as_ref()) {
                            for container_status in container_statuses {
                                if let Some(container_id) = &container_status.container_id {
                                    let container_id = container_id.split("://").nth(1).unwrap_or(container_id).to_string();
                                    cache.insert(
                                        container_id.clone(),
                                        PodInfo {
                                            namespace: namespace.clone(),
                                            pod_name: name.clone(),
                                        },
                                    );
                                    println!("Found container id: {} in pod: {} in namespace: {}", container_id, name, namespace);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Failed to list pods: {}", e),
        }

        PodCache {
            container_pod_cache: Arc::new(RwLock::new(cache)),
            pid_container_cache: Arc::new(RwLock::new(get_container_ids().unwrap_or_else(|_| HashMap::new()))),
        }
    }

    pub fn get_container_id_by_pid(&self, pid: u32) -> Option<String> {
        self.pid_container_cache
            .read()
            .expect("Failed to acquire read lock")
            .get(&pid)
            .cloned()
    }

    pub fn get_pod_info_by_container_id(&self, container_id: &str) -> Option<PodInfo> {
        self.container_pod_cache
            .read()
            .expect("Failed to acquire read lock")
            .get(container_id)
            .cloned()
    }

    pub fn set_pid_container_cache(&mut self, new_cache: HashMap<u32, String>) {
        // self.pid_container_cache = new_cache;
        let mut pid_container_cache = self.pid_container_cache.write().expect("Failed to acquire write lock");
        for (pid, container_id) in &new_cache {
            pid_container_cache.insert(*pid, container_id.clone());
        }
        // Remove entries that are not in the new cache
        pid_container_cache.retain(|pid, _| new_cache.contains_key(pid));
    }

    pub fn update_pid_container_cache(&mut self) {
        match get_container_ids() {
            Ok(new_cache) => self.set_pid_container_cache(new_cache),
            Err(e) => eprintln!("Failed to update PID container cache: {}", e),
        }
    }

    pub fn get_pids(&self) -> Vec<u32> {
        self.pid_container_cache
            .read()
            .expect("Failed to acquire read lock")
            .keys()
            .cloned()
            .collect()
    }
}

fn get_container_ids() -> Result<std::collections::HashMap<u32, String>, anyhow::Error> {
    let mut pid_to_container_id = std::collections::HashMap::new();
    // since this application will be running privileged with access to /proc, we get get the container ids from /proc/<pid>/cgroup (file)
    // the cgroup file contains the cgroup hierarchy for the process, including the container id
    // we can parse the cgroup file to get the container id
    // for example, a cgroup can look like this:
    // ::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod0f1c0a01_f9b0_41ae_9d7e_15104d4f03ba.slice/cri-containerd-ac943021d695b61c1f27c60f6a634564c4f4c2dcb60f9a950e4a0b040df59228.scope
    // so given that we already have the PID, we can read the cgroup file and parse it to get the container id
    // the container id is the last part of the cgroup path, so we can split the path by / and get the last part (while cutting off the .scope part)
    // we can also check if the cgroup path contains cri-containerd, which is a good indicator that this is a container
    let proc_dir = fs::read_dir("/proc")?;
    for entry in proc_dir {
        let entry = entry?;
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            let cgroup_path = format!("/proc/{}/cgroup", pid);
            if let Ok(cgroup_content) = fs::read_to_string(&cgroup_path) {
                for line in cgroup_content.lines() {
                    if let Some(container_id) = line.split('/').last() {
                        if container_id.contains("cri-containerd") {
                            let container_id = container_id.trim_end_matches(".scope");
                            let container_id = container_id.trim_start_matches("cri-containerd-");
                            println!("Found container id: {} for pid: {}", container_id, pid);
                            pid_to_container_id.insert(pid, container_id.to_string());
                        }
                    }
                }
            }
        }
    }

    Ok(pid_to_container_id)
}


// [todo] informer for updating podcache to watch for any updates or pod churn
// [todo] container id to pid mapping cache needs to be updated periodically
