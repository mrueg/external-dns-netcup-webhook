# external-dns-netcup-webhook

External-DNS Webhook Provider to manage Netcup DNS Records

> [!NOTE]
> This repository is not affiliated with Netcup.

> [!WARNING]
> Completely untested code. Might eat your DNS records. You have been warned.


## Setting up external-dns for Netcup

This tutorial describes how to setup external-dns for usage within a Kubernetes cluster using Netcup as the domain provider.

Make sure to use external-dns version 0.14.0 or later for this tutorial.

### Creating Netcup Credentials

A secret containing the a Netcup API token and an API Password is needed for this provider. You can get a token for your user [here](https://www.customercontrolpanel.de/daten_aendern.php?sprung=api).

To create the API token secret you can run `kubectl create secret generic netcup-api-key --from-literal=NETCUP_API_KEY=<replace-with-your-access-token>`.

To create the API password secret you can run `kubectl create secret generic netcup-api-password --from-literal=NETCUP_API_PASSWORD=<replace-with-your-access-token>`.

### Deploy external-dns

Connect your `kubectl` client to the cluster you want to test external-dns with.

Besides the API key and password, it is mandatory to provide a customer id as well as a list of DNS zones you want external-dns to manage. The hosted DNS zones will be provides via the `--domain-filter`.

Then apply one of the following manifests file to deploy external-dns.

```
$ kubectl create -f example/external-dns.yaml
```

[embedmd]:# (example/external-dns.yaml)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-dns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: external-dns
rules:
- apiGroups: [""]
  resources: ["services","endpoints","pods"]
  verbs: ["get","watch","list"]
- apiGroups: ["extensions","networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get","watch","list"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: external-dns-viewer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: external-dns
subjects:
- kind: ServiceAccount
  name: external-dns
  namespace: default
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
spec:
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: external-dns
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
      - name: external-dns
        image: registry.k8s.io/external-dns/external-dns:v0.17.0
        args:
        - --log-level=debug
        - --source=ingress
        - --source=service
        - --provider=webhook
      - name: external-dns-webhook-provider
        image: ghcr.io/mrueg/external-dns-netcup-webhook:latest
        imagePullPolicy: Always
        args:
        - --log.level=debug
        - --domain-filter=YOUR_DOMAIN
        - --netcup-customer-id=YOUR_ID
        env:
        - name: NETCUP_API_KEY
          valueFrom:
            secretKeyRef:
              key: NETCUP_API_KEY
              name: netcup-api-key
        - name: NETCUP_API_PASSWORD
          valueFrom:
            secretKeyRef:
              key: NETCUP_API_PASSWORD
              name: netcup-api-password
        ports:
          - containerPort: 8080
            name: http-webhook
        livenessProbe:
          failureThreshold: 2
          httpGet:
            path: /healthz
            port: http-webhook
            scheme: HTTP
          initialDelaySeconds: 10
          periodSeconds: 10
          successThreshold: 1
          timeoutSeconds: 5

```

### Deploying an Nginx Service

Create the deployment and service:

```
$ kubectl create -f example/nginx.yaml
```

[embedmd]:# (example/nginx.yaml)
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx
        name: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    external-dns.alpha.kubernetes.io/hostname: test.example.com
    external-dns.alpha.kubernetes.io/internal-hostname: internaltest.example.com
spec:
  selector:
    app: nginx
  type: LoadBalancer
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
```

Note the annotation on the service; use the same hostname as the Netcup DNS zone created above. The annotation may also be a subdomain
of the DNS zone (e.g. 'www.example.com').

By setting the TTL annotation on the service, you have to pass a valid TTL, which must be 120 or above.
This annotation is optional, if you won't set it, it will be 1 (automatic) which is 300.

external-dns uses this annotation to determine what services should be registered with DNS.  Removing the annotation
will cause external-dns to remove the corresponding DNS records.

Depending where you run your service it can take a little while for your cloud provider to create an external IP for the service.

Once the service has an external IP assigned, external-dns will notice the new service IP address and synchronize
the Netcup DNS records.

### Verifying Netcup DNS records

Check your [Netcup domain overview](https://www.customercontrolpanel.de/domains.php) to view the domains associated with your Netcup account. There you can view the records for each domain.

The records should show the external IP address of the service as the A record for your domain.

### Cleanup

Now that we have verified that external-dns will automatically manage Netcup DNS records, we can delete the tutorial's example:

```
$ kubectl delete -f example/nginx.yaml
$ kubectl delete -f example/external-dns.yaml
```
