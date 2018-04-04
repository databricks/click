## 0.3.2 / 2018-04-04
* [feature] GKE authentication support
* [feature] support insecure\_skip\_tls\_verify in config
* [enhancement] use KUBECONFIG environment variable to identify config file
* [enhancement] context command with no arguments prints all available contexts
* [enhancement] logs command on a pod with one container will get logs for that container
* [enhancement] describe on a secret shows token value, mirroring kubectl
* [bugfix] logs command now works for clusters using an IP address
* [bugfix] remove a number of unwraps that could cause unhelpful panics
