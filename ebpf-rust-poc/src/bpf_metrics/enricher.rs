use kube::{Client, api::{Api, ListParams}};
use k8s_openapi::api::core::v1::Pod;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct PodInfo {
    pub namespace: String,
    pub pod_name: String,
}

// map of <container_id, (namespace, pod_name)>
pub struct PodCache {
    pub cache: HashMap<String, PodInfo>,
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
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Failed to list pods: {}", e),
        }

        PodCache {
            cache,
        }
    }
}

// [todo] informer for updating podcache to watch for any updates or pod churn
