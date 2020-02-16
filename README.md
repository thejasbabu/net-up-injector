# Net-up sidecar injector

This uses the `MutatingAdmissionWebhook` to mutate the kubernetes resources based on labels and annotations.

Currently it mutates the following
1. Injects a sniffer proxy to sniff network packets using BPF expressions


## TODO

1. Inject init container that will set-up ip-table rules to redirect traffic through the sidecar sniffer

## Set-up
1. Create the certificate to be used by the injector by running the `./scripts/create-cert.sh` and pass the required flag. This creates a secret in the namespace provided which is used in the next step

1. Deploy the deployment object 
```$xslt
kubectl apply -f scripts/deployment.yaml
kubectl apply -f scripts/configmap.yaml
```

1. Add the `MutatingWebhookConfiguration` by running the below commands 

```$xslt
export CA_BUNDLE=$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}')
cat scripts/mutatingwebhook.yaml | envsubst | kubectl apply -f -
```
1. Mark the namespace to be injectable by adding the annotation `net-up-injector: enabled` to the namespace  

1. Add the following to the deployment.spec.template.metadata.annotations or pod.metadata.annotation
   
   ```$xslt
   	"thejasbabu.packetSniffer.inject": "enabled"
   ```
 
## Configuration


One can also change the default values by adding the network interface to sniff as well as custom bpf expression

```$xslt
	"thejasbabu.packetSniffer.networkInterface": "eth0"
	"thejasbabu.packetSniffer.bpfExpr": "tcp and dst port 80"

```

After successful injection, the following annotation will be added to the pod.

```$xslt
	"thejasbabu.packetSniffer.status": "injected"
```

```$xslt

```
