from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from .models import User
from . import db
from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
from kubernetes.utils import create_from_yaml
import subprocess
import ipaddress
import yaml
import tempfile
import datetime
from kubernetes.client import V1ConfigMap

bp = Blueprint('routes', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        if not username:
            error = 'Un nom d\'utilisateur est requis.'
        elif not password:
            error = 'Un mot de passe est requis.'
        elif User.query.filter_by(username=username).first():
            error = f"L'utilisateur {username} est déjà enregistré."

        if error is None:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            create_namespace_for_user(username)
            flash('Inscription réussie. Connectez-vous.', 'success')
            return redirect(url_for('routes.login'))

        flash(error, 'error')

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        user = User.query.filter_by(username=username).first()

        if user is None:
            error = 'Nom d\'utilisateur incorrect.'
        elif not user.check_password(password):
            error = 'Mot de passe incorrect.'

        if error is None:
            session.clear()
            session['user_id'] = username
            return redirect(url_for('routes.dashboard'))

        flash(error, 'error')

    return render_template('auth/login.html')

@bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    quota_name = f"quota-{ns_name}"
    ippool_name = f"ippool-{ns_name}"

    current_quota = None
    cidr = None
    error = None
    services_info = None

    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException:
            error = "Impossible de charger la configuration Kubernetes."
            flash(error, "error")

    if not error:
        try:
            api_client = client.ApiClient()
            v1 = client.CoreV1Api(api_client)
            dyn_client = DynamicClient(api_client)

            # Récupérer les quotas de ressources
            try:
                api_response = v1.read_namespaced_resource_quota(name=quota_name, namespace=ns_name)
                current_quota = api_response.spec.hard
            except client.exceptions.ApiException as e:
                if e.status != 404:
                    flash(f"Erreur en récupérant les quotas: {e.reason}", "error")

            # Récupérer le CIDR du pool d'IP
            try:
                ippool_api = dyn_client.resources.get(api_version="crd.projectcalico.org/v1", kind="IPPool")
                ippool = ippool_api.get(name=ippool_name)
                cidr = ippool.spec.cidr
            except Exception as e:
                if "NotFound" not in str(e):
                    flash(f"Erreur en récupérant le pool d'IP: {str(e)}", "error")

            # Récupérer les services déployés (pour affichage dans dashboard)
            apps_v1 = client.AppsV1Api(api_client)
            k8s_services = v1.list_namespaced_service(namespace=ns_name).items
            deployments = {d.metadata.name: d for d in apps_v1.list_namespaced_deployment(namespace=ns_name).items}
            pods = v1.list_namespaced_pod(namespace=ns_name).items
            # Récupération de l'IP du nœud (premier nœud Ready)
            node_ip = None
            try:
                nodes = v1.list_node().items
                for node in nodes:
                    for status in node.status.conditions:
                        if status.type == "Ready" and status.status == "True":
                            for addr in node.status.addresses:
                                if addr.type == "InternalIP":
                                    node_ip = addr.address
                                    break
                            if node_ip:
                                break
                    if node_ip:
                        break
            except Exception:
                pass
            services_info = []
            for svc in k8s_services:
                name = svc.metadata.name
                ports = [p.node_port if p.node_port else p.port for p in svc.spec.ports]
                
                pod_status = "Inconnu"
                pod_name = None
                selector = svc.spec.selector
                
                matching_pods = []
                if selector:
                    for pod in pods:
                        pod_labels = pod.metadata.labels
                        if pod_labels and all(item in pod_labels.items() for item in selector.items()):
                            matching_pods.append(pod)
                
                if matching_pods:
                    running_pod = next((p for p in matching_pods if p.status.phase == 'Running'), None)
                    if running_pod:
                        pod_status = running_pod.status.phase
                        pod_name = running_pod.metadata.name
                    else:
                        pod_status = matching_pods[0].status.phase
                        pod_name = matching_pods[0].metadata.name
                
                nodeport_url = None
                console_url = None
                if svc.spec.type == "NodePort" and node_ip:
                    for p in svc.spec.ports:
                        if hasattr(p, 'name') and p.name == 'console' and p.node_port:
                            console_url = f"http://{node_ip}:{p.node_port}"
                        elif p.node_port and not nodeport_url:
                            nodeport_url = f"http://{node_ip}:{p.node_port}"
                services_info.append({
                    'name': name,
                    'ports': ports,
                    'status': pod_status,
                    'pod_name': pod_name,
                    'nodeport_url': nodeport_url,
                    'console_url': console_url
                })
        except Exception as e:
            flash(f"Une erreur inattendue est survenue: {str(e)}", "error")

    return render_template('dashboard/dashboard.html', username=username, quota=current_quota, cidr=cidr, error=error, services=services_info, ns_name=ns_name)

@bp.route('/resources', methods=['GET', 'POST'])
def resources():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    username = session['user_id']
    ns_name = f"user-{username}"
    quota_name = f"quota-{ns_name}"

    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException:
            flash("Impossible de charger la configuration Kubernetes.", "error")
            return render_template('dashboard/resources.html', quota=None, username=username, error=True)

    api_client = client.ApiClient()
    v1 = client.CoreV1Api(api_client)

    current_quota = None
    try:
        api_response = v1.read_namespaced_resource_quota(name=quota_name, namespace=ns_name)
        current_quota = api_response.spec.hard
    except client.exceptions.ApiException as e:
        if e.status != 404:
            flash(f"Erreur en récupérant les quotas: {e.reason}", "error")

    if request.method == 'POST':
        hard_limits = {
            'requests.cpu': request.form.get('requests_cpu'),
            'requests.memory': request.form.get('requests_memory'),
            'limits.cpu': request.form.get('limits_cpu'),
            'limits.memory': request.form.get('limits_memory'),
            'pods': request.form.get('pods'),
            'services': request.form.get('services')
        }
        
        hard_limits = {k: v for k, v in hard_limits.items() if v}

        if not hard_limits:
            try:
                # S'il n'y a pas de limites, on supprime le quota existant
                v1.delete_namespaced_resource_quota(name=quota_name, namespace=ns_name)
                flash("Quotas supprimés.", "success")
            except client.exceptions.ApiException as e:
                if e.status != 404:
                    flash(f"Erreur lors de la suppression des quotas: {e.reason}", "error")
            return redirect(url_for('routes.resources'))

        quota_spec = client.V1ResourceQuotaSpec(hard=hard_limits)
        quota_body = client.V1ResourceQuota(
            metadata=client.V1ObjectMeta(name=quota_name),
            spec=quota_spec
        )

        try:
            # Vérifie si le quota existe déjà pour décider de créer ou remplacer
            v1.read_namespaced_resource_quota(name=quota_name, namespace=ns_name)
            v1.replace_namespaced_resource_quota(name=quota_name, namespace=ns_name, body=quota_body)
            flash('Quotas mis à jour avec succès.', 'success')
        except client.exceptions.ApiException as e:
            if e.status == 404:
                try:
                    v1.create_namespaced_resource_quota(namespace=ns_name, body=quota_body)
                    flash('Quotas créés avec succès.', 'success')
                except client.exceptions.ApiException as create_e:
                    flash(f"Erreur lors de la création des quotas: {create_e.reason}", "error")
            else:
                flash(f"Erreur lors de la mise à jour des quotas: {e.reason}", "error")
        
        return redirect(url_for('routes.resources'))

    return render_template('dashboard/resources.html', quota=current_quota, username=username)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('routes.index')) 

def get_used_cidrs(api_client):
    dyn_client = DynamicClient(api_client)
    ippool_api = dyn_client.resources.get(api_version="crd.projectcalico.org/v1", kind="IPPool")
    ippools = ippool_api.get()
    return [item.spec['cidr'] for item in ippools.items]

def get_next_cidr(api_client):
    used = set(get_used_cidrs(api_client))
    for i in range(16, 251):
        cidr = f"192.168.{i}.0/24"
        if cidr not in used:
            return cidr
    raise Exception("Plus de CIDR disponibles dans la plage 192.168.0.0/16")

def create_calico_ippool(api_client, name, cidr):
    dyn_client = DynamicClient(api_client)
    ippool_api = dyn_client.resources.get(api_version="crd.projectcalico.org/v1", kind="IPPool")
    ippool_manifest = {
        "apiVersion": "crd.projectcalico.org/v1",
        "kind": "IPPool",
        "metadata": {"name": name},
        "spec": {
            "cidr": cidr,
            "ipipMode": "Never",
            "natOutgoing": True,
            "vxlanMode": "CrossSubnet",
            "nodeSelector": "all()"
        }
    }
    try:
        ippool_api.create(body=ippool_manifest)
    except Exception as e:
        if 'AlreadyExists' not in str(e):
            raise

def annotate_namespace(api_client, ns_name, ippool_name):
    v1 = client.CoreV1Api(api_client)
    body = {
        "metadata": {
            "annotations": {
                "cni.projectcalico.org/ipv4pools": f'["{ippool_name}"]'
            }
        }
    }
    v1.patch_namespace(ns_name, body)

def create_namespace_for_user(username):
    config.load_incluster_config()
    api_client = client.ApiClient()
    v1 = client.CoreV1Api(api_client)
    ns_name = f"user-{username}"
    ns = client.V1Namespace(metadata=client.V1ObjectMeta(name=ns_name))
    try:
        v1.create_namespace(ns)
    except client.exceptions.ApiException as e:
        if e.status != 409:
            raise
    # Création du pool Calico et annotation
    cidr = get_next_cidr(api_client)
    ippool_name = f"ippool-{ns_name}"
    create_calico_ippool(api_client, ippool_name, cidr)
    annotate_namespace(api_client, ns_name, ippool_name)

    # Création du ResourceQuota par défaut
    quota_name = f"quota-{ns_name}"
    quota_spec = client.V1ResourceQuotaSpec(hard={
        'requests.cpu': '1',
        'requests.memory': '1Gi',
        'limits.cpu': '1',
        'limits.memory': '1Gi',
        'pods': '5',
        'services': '2'
    })
    quota_body = client.V1ResourceQuota(
        metadata=client.V1ObjectMeta(name=quota_name),
        spec=quota_spec
    )
    try:
        v1.create_namespaced_resource_quota(namespace=ns_name, body=quota_body)
    except client.exceptions.ApiException as e:
        if e.status != 409:
            raise
    return cidr

def delete_namespace_for_user(username):
    config.load_incluster_config()
    api_client = client.ApiClient()
    v1 = client.CoreV1Api(api_client)
    ns_name = f"user-{username}"
    ippool_name = f"ippool-{ns_name}"

    # Supprime le namespace
    try:
        v1.delete_namespace(ns_name)
    except client.exceptions.ApiException as e:
        if e.status != 404:  # 404 = Not found
            raise

    # Supprime l'IPPool Calico associé
    try:
        dyn_client = DynamicClient(api_client)
        ippool_api = dyn_client.resources.get(api_version="crd.projectcalico.org/v1", kind="IPPool")
        ippool_api.delete(name=ippool_name)
    except Exception as e:
        # Ignore si le pool n'existe pas déjà
        if "NotFound" not in str(e):
            raise

@bp.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    user = User.query.filter_by(username=session['user_id']).first()
    if request.method == 'POST':
        username = user.username
        # Supprime le namespace Kubernetes
        delete_namespace_for_user(username)
        # Supprime l'utilisateur de la base
        db.session.delete(user)
        db.session.commit()
        session.clear()
        flash('Votre compte a été supprimé.')
        return redirect(url_for('routes.index'))
    return render_template('auth/delete_account.html', user=user)

@bp.route('/deploy/wordpress', methods=['GET', 'POST'])
def deploy_wordpress():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    message = None
    if request.method == 'POST':
        php_version = request.form['php_version']
        theme = request.form['theme']
        storage_val = int(request.form['storage'])
        # Conversion curseur : <1024 => Mi, >=1024 => Gi
        if storage_val < 1024:
            storage = f"{storage_val}Mi"
        else:
            storage = f"{round(storage_val/1024, 2)}Gi"
        backup = request.form.get('backup', 'none')
        # Récupération dynamique des ressources
        requests_cpu = request.form.get('requests_cpu', '250m')
        limits_cpu = request.form.get('limits_cpu', '500m')
        requests_memory = request.form.get('requests_memory', '512Mi')
        limits_memory = request.form.get('limits_memory', '1Gi')
        db_host = request.form.get('db_host') or 'postgres-service'
        db_name = request.form.get('db_name') or 'wordpress'
        db_user = request.form.get('db_user') or 'wpuser'
        db_password = request.form.get('db_password') or 'wppass'
        db_type = request.form.get('db_type') or 'pgsql'
        # Manifest YAML WordPress avec initContainer pour PG4WP
        manifest = f'''
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: wp-pvc
  namespace: {ns_name}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: {storage}
  storageClassName: local-path
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wordpress
  namespace: {ns_name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wordpress
  template:
    metadata:
      labels:
        app: wordpress
    spec:
      initContainers:
      - name: install-pg4wp
        image: alpine:3.18
        command:
          - sh
          - -c
          - |
            apk add --no-cache wget unzip
            wget https://github.com/PostgreSQL-For-Wordpress/postgresql-for-wordpress/archive/refs/tags/v3.3.1.zip -O /tmp/pg4wp.zip
            unzip /tmp/pg4wp.zip -d /tmp/
            cp -r /tmp/postgresql-for-wordpress-3.3.1/pg4wp /pg4wp/
            cp /tmp/postgresql-for-wordpress-3.3.1/pg4wp/db.php /pg4wp/db.php
        volumeMounts:
        - name: pg4wp
          mountPath: /pg4wp
        resources:
          requests:
            cpu: "50m"
            memory: "64Mi"
          limits:
            cpu: "100m"
            memory: "128Mi"
      containers:
      - name: wordpress
        image: marius790000/wordpress-pgsql:latest
        resources:
          requests:
            cpu: "{requests_cpu}"
            memory: "{requests_memory}"
          limits:
            cpu: "{limits_cpu}"
            memory: "{limits_memory}"
        env:
        - name: WORDPRESS_DB_HOST
          value: "{db_host}.{ns_name}.svc.cluster.local"
        - name: WORDPRESS_DB_USER
          value: "{db_user}"
        - name: WORDPRESS_DB_PASSWORD
          value: "{db_password}"
        - name: WORDPRESS_DB_NAME
          value: "{db_name}"
        volumeMounts:
        - name: wp-data
          mountPath: /var/www/html
        - name: pg4wp
          mountPath: /var/www/html/wp-content/db.php
          subPath: db.php
        - name: pg4wp
          mountPath: /var/www/html/wp-content/pg4wp
          subPath: pg4wp
      volumes:
      - name: wp-data
        persistentVolumeClaim:
          claimName: wp-pvc
      - name: pg4wp
        emptyDir: {{}}
---
apiVersion: v1
kind: Service
metadata:
  name: wordpress
  namespace: {ns_name}
spec:
  selector:
    app: wordpress
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: NodePort
'''
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        api_client = client.ApiClient()
        try:
            with tempfile.NamedTemporaryFile('w', delete=False) as f:
                f.write(manifest)
                f.flush()
                create_from_yaml(api_client, f.name, namespace=ns_name)
            message = f"Déploiement WordPress lancé avec succès ! (Sauvegarde : {backup})"
        except Exception as e:
            if 'AlreadyExists' in str(e) or '409' in str(e):
                message = "Erreur : un déploiement WordPress existe déjà dans ce namespace. Supprime-le avant de redéployer."
            else:
                message = f"Erreur lors du déploiement : {str(e)}"
    return render_template('dashboard/deploy_wordpress.html', message=message)

@bp.route('/deploy/postgresql', methods=['GET', 'POST'])
def deploy_postgresql():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    message = None
    if request.method == 'POST':
        version = request.form['version']
        storage_val = int(request.form['storage'])
        if storage_val < 1024:
            storage = f"{storage_val}Mi"
        else:
            storage = f"{round(storage_val/1024, 2)}Gi"
        
        ips = [request.form.get(f'ip{i}', '').strip() for i in range(1, 6) if request.form.get(f'ip{i}', '').strip()]
        
        retention = request.form.get('retention', '7')
        backup = request.form.get('backup', 'none')
        backup_label = {'none': 'Aucune', 'daily': 'Quotidienne', 'weekly': 'Hebdomadaire', 'monthly': 'Mensuelle'}.get(backup, backup)

        # Récupération des credentials
        postgres_db = request.form.get('postgres_db', 'wordpress')
        postgres_user = request.form.get('postgres_user', 'wpuser')
        postgres_password = request.form.get('postgres_password', 'wppass')

        # Récupération dynamique des ressources (comme pour WordPress)
        requests_cpu = request.form.get('requests_cpu', '250m')
        limits_cpu = request.form.get('limits_cpu', '500m')
        requests_memory = request.form.get('requests_memory', '512Mi')
        limits_memory = request.form.get('limits_memory', '1Gi')

        manifests = f"""
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: {ns_name}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: {storage}
  storageClassName: local-path
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-service
  namespace: {ns_name}
  labels:
    app: postgres
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:{version}
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: "{postgres_db}"
        - name: POSTGRES_USER
          value: "{postgres_user}"
        - name: POSTGRES_PASSWORD
          value: "{postgres_password}"
        resources:
          requests:
            cpu: "{requests_cpu}"
            memory: "{requests_memory}"
          limits:
            cpu: "{limits_cpu}"
            memory: "{limits_memory}"
        volumeMounts:
        - mountPath: /var/lib/postgresql/data
          name: postgres-storage
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: {ns_name}
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
"""
        if ips:
            network_policy_yaml = f"""
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: postgres-netpol
  namespace: {ns_name}
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {{}}
"""
            for ip in ips:
                try:
                    ipaddress.ip_network(ip, strict=False)
                    cidr = ip if '/' in ip else f"{ip}/32"
                    network_policy_yaml += f"""
    - ipBlock:
        cidr: {cidr}
"""
                except ValueError:
                    flash(f"Adresse IP/CIDR invalide ignorée : {ip}", "warning")
            
            network_policy_yaml += """
    ports:
    - protocol: TCP
      port: 5432
"""
            manifests += network_policy_yaml

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        
        api_client = client.ApiClient()
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as temp_file:
                temp_file.write(manifests)
                temp_file.flush()
                create_from_yaml(api_client, yaml_file=temp_file.name, namespace=ns_name)
            
            message = f"Déploiement PostgreSQL (version {version}) lancé avec succès. Stockage: {storage}, Sauvegarde: {backup_label}, Rétention: {retention} jours."
            flash(message, 'success')

            # Connexion automatique à WordPress si demandé
            if request.form.get('connect_wordpress'):
                try:
                    apps_v1 = client.AppsV1Api(api_client)
                    # Vérifier si le déploiement WordPress existe
                    deployment = apps_v1.read_namespaced_deployment(name="wordpress", namespace=ns_name)
                    # Mettre à jour les variables d'environnement
                    env = [
                        client.V1EnvVar(name="WORDPRESS_DB_HOST", value="postgres-service"),
                        client.V1EnvVar(name="WORDPRESS_DB_USER", value=postgres_user),
                        client.V1EnvVar(name="WORDPRESS_DB_PASSWORD", value=postgres_password),
                        client.V1EnvVar(name="WORDPRESS_DB_NAME", value=postgres_db),
                    ]
                    deployment.spec.template.spec.containers[0].env = env
                    apps_v1.patch_namespaced_deployment(name="wordpress", namespace=ns_name, body=deployment)
                    # Forcer le redémarrage du pod WordPress
                    apps_v1.patch_namespaced_deployment(
                        name="wordpress",
                        namespace=ns_name,
                        body={"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": datetime.datetime.utcnow().isoformat()}}}}}
                    )
                    flash("Connexion automatique à WordPress effectuée !", "success")
                except Exception as e:
                    flash(f"Connexion à WordPress ignorée (non installé ou erreur) : {str(e)}", "warning")
        except Exception as e:
            if 'AlreadyExists' in str(e):
                message = "Un déploiement PostgreSQL, un service ou un PVC avec le même nom existe déjà."
                flash(message, 'error')
            else:
                message = f"Erreur lors du déploiement de PostgreSQL : {str(e)}"
                flash(message, 'error')
        
        return redirect(url_for('routes.deploy_postgresql'))

    return render_template('dashboard/deploy_postgresql.html', message=None)

@bp.route('/deploy/s3', methods=['GET', 'POST'])
def deploy_s3():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    message = None
    if request.method == 'POST':
        try:
            # Chargement config K8s
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()
            api_client = client.ApiClient()
            v1 = client.CoreV1Api(api_client)
            apps_v1 = client.AppsV1Api(api_client)
            # Vérifier si un déploiement S3 existe déjà
            already_exists = False
            try:
                apps_v1.read_namespaced_deployment(name="minio", namespace=ns_name)
                already_exists = True
            except client.exceptions.ApiException as e:
                if e.status != 404:
                    raise
            try:
                v1.read_namespaced_service(name="minio", namespace=ns_name)
                already_exists = True
            except client.exceptions.ApiException as e:
                if e.status != 404:
                    raise
            try:
                v1.read_namespaced_persistent_volume_claim(name="s3-pvc", namespace=ns_name)
                already_exists = True
            except client.exceptions.ApiException as e:
                if e.status != 404:
                    raise
            if already_exists:
                message = "Erreur : un déploiement S3 existe déjà dans ce namespace. Supprime-le avant de redéployer."
                return render_template('dashboard/deploy_s3.html', message=message)
            # Récupération des options du formulaire
            storage_val = int(request.form['storage'])
            if storage_val < 1024:
                storage = f"{storage_val}Mi"
            else:
                storage = f"{round(storage_val/1024, 2)}Gi"
            encryption = request.form.get('encryption', 'off') == 'on'
            lifecycle = request.form.get('lifecycle', 'illimite')
            access_type = request.form.get('access_type', 'prive')
            enabled = request.form.get('enabled', 'on') == 'on'
            minio_user = request.form.get('minio_user', 'minioadmin')
            minio_password = request.form.get('minio_password', 'minioadmin')
            minio_env = [
                {'name': 'MINIO_ROOT_USER', 'value': minio_user},
                {'name': 'MINIO_ROOT_PASSWORD', 'value': minio_password},
            ]
            if encryption:
                minio_env.append({'name': 'MINIO_KMS_AUTO_ENCRYPTION', 'value': 'on'})
            if lifecycle == '30j':
                lifecycle_config = '{"Rules":[{"ID":"expire-30d","Status":"Enabled","Expiration":{"Days":30},"Filter":{"Prefix":""}}]}'
            elif lifecycle == '1an':
                lifecycle_config = '{"Rules":[{"ID":"expire-1y","Status":"Enabled","Expiration":{"Days":365},"Filter":{"Prefix":""}}]}'
            else:
                lifecycle_config = '{"Rules":[]}'
            env_yaml = '\n'.join([
                f'          - name: {e["name"]}\n            value: "{e["value"]}"' for e in minio_env
            ])
            if not enabled:
                message = "Service S3 désactivé."
                return render_template('dashboard/deploy_s3.html', message=message)
            # Création du ConfigMap via l'API
            configmap_body = V1ConfigMap(
                metadata=client.V1ObjectMeta(name="minio-lifecycle", namespace=ns_name),
                data={"lifecycle.json": lifecycle_config}
            )
            try:
                v1.create_namespaced_config_map(namespace=ns_name, body=configmap_body)
            except client.exceptions.ApiException as e:
                if e.status == 409:
                    v1.replace_namespaced_config_map(name="minio-lifecycle", namespace=ns_name, body=configmap_body)
                else:
                    raise
            # Récupération dynamique des ressources
            requests_cpu = request.form.get('requests_cpu', '100m')
            limits_cpu = request.form.get('limits_cpu', '500m')
            requests_memory = request.form.get('requests_memory', '256Mi')
            limits_memory = request.form.get('limits_memory', '1Gi')
            # Création du manifeste YAML complet
            other_manifest = f'''
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: s3-pvc
  namespace: {ns_name}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: {storage}
  storageClassName: local-path
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minio
  namespace: {ns_name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: minio
  template:
    metadata:
      labels:
        app: minio
    spec:
      containers:
      - name: minio
        image: quay.io/minio/minio:latest
        args:
          - server
          - /data
          - --console-address
          - ":9001"
        env:
{env_yaml}
        ports:
          - containerPort: 9000
            name: api
          - containerPort: 9001
            name: console
        volumeMounts:
          - name: data
            mountPath: /data
          - name: lifecycle
            mountPath: /etc/minio/
        resources:
          requests:
            cpu: "{requests_cpu}"
            memory: "{requests_memory}"
          limits:
            cpu: "{limits_cpu}"
            memory: "{limits_memory}"
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: s3-pvc
        - name: lifecycle
          configMap:
            name: minio-lifecycle
---
apiVersion: v1
kind: Service
metadata:
  name: minio
  namespace: {ns_name}
spec:
  selector:
    app: minio
  ports:
    - name: api
      protocol: TCP
      port: 9000
      targetPort: 9000
      nodePort: 32000
    - name: console
      protocol: TCP
      port: 9001
      targetPort: 9001
      nodePort: 32001
  type: NodePort
'''
            with tempfile.NamedTemporaryFile('w', delete=False) as f2:
                f2.write(other_manifest)
                f2.flush()
                create_from_yaml(api_client, f2.name, namespace=ns_name)
            message = f"Déploiement S3 lancé avec succès ! (Stockage : {storage}, Chiffrement : {'Oui' if encryption else 'Non'}, Cycle de vie : {lifecycle}, Accès : {access_type})"
        except Exception as e:
            if 'AlreadyExists' in str(e) or '409' in str(e):
                message = "Erreur : un déploiement S3 existe déjà dans ce namespace. Supprime-le avant de redéployer."
            else:
                message = f"Erreur lors du déploiement : {str(e)}"
    return render_template('dashboard/deploy_s3.html', message=message)

@bp.route('/services')
def services():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    api_client = client.ApiClient()
    v1 = client.CoreV1Api(api_client)
    apps_v1 = client.AppsV1Api(api_client)
    # Liste des services
    k8s_services = v1.list_namespaced_service(namespace=ns_name).items
    # Liste des deployments
    deployments = {d.metadata.name: d for d in apps_v1.list_namespaced_deployment(namespace=ns_name).items}
    # Liste des pods
    pods = v1.list_namespaced_pod(namespace=ns_name).items
    # Récupération de l'IP du nœud (premier nœud Ready)
    node_ip = None
    try:
        nodes = v1.list_node().items
        for node in nodes:
            for status in node.status.conditions:
                if status.type == "Ready" and status.status == "True":
                    for addr in node.status.addresses:
                        if addr.type == "InternalIP":
                            node_ip = addr.address
                            break
                    if node_ip:
                        break
            if node_ip:
                break
    except Exception:
        pass
    # Construction de la liste des services avec état, port et URL d'accès
    services_info = []
    for svc in k8s_services:
        name = svc.metadata.name
        ports = [p.node_port if p.node_port else p.port for p in svc.spec.ports]
        
        pod_status = "Inconnu"
        pod_name = None
        selector = svc.spec.selector
        
        matching_pods = []
        if selector:
            for pod in pods:
                pod_labels = pod.metadata.labels
                if pod_labels and all(item in pod_labels.items() for item in selector.items()):
                    matching_pods.append(pod)

        if matching_pods:
            running_pod = next((p for p in matching_pods if p.status.phase == 'Running'), None)
            if running_pod:
                pod_status = running_pod.status.phase
                pod_name = running_pod.metadata.name
            else:
                pod_status = matching_pods[0].status.phase
                pod_name = matching_pods[0].metadata.name

        # Générer l'URL d'accès si NodePort
        nodeport_url = None
        console_url = None
        if svc.spec.type == "NodePort" and node_ip:
            for p in svc.spec.ports:
                if hasattr(p, 'name') and p.name == 'console' and p.node_port:
                    console_url = f"http://{node_ip}:{p.node_port}"
                elif p.node_port and not nodeport_url:
                    nodeport_url = f"http://{node_ip}:{p.node_port}"
        services_info.append({
            'name': name,
            'ports': ports,
            'status': pod_status,
            'pod_name': pod_name,
            'nodeport_url': nodeport_url,
            'console_url': console_url
        })
    return render_template('dashboard/services.html', services=services_info, ns_name=ns_name)

@bp.route('/delete/wordpress', methods=['POST'])
def delete_wordpress():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    api_client = client.ApiClient()
    v1 = client.CoreV1Api(api_client)
    apps_v1 = client.AppsV1Api(api_client)
    # Suppression du Deployment
    try:
        apps_v1.delete_namespaced_deployment(name="wordpress", namespace=ns_name)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            flash(f"Erreur lors de la suppression du deployment : {e.reason}", "error")
    # Suppression du Service
    try:
        v1.delete_namespaced_service(name="wordpress", namespace=ns_name)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            flash(f"Erreur lors de la suppression du service : {e.reason}", "error")
    # Suppression du PVC
    try:
        v1.delete_namespaced_persistent_volume_claim(name="wp-pvc", namespace=ns_name)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            flash(f"Erreur lors de la suppression du PVC : {e.reason}", "error")
    flash("WordPress et ses ressources ont été supprimés.", "success")
    return redirect(url_for('routes.deploy_wordpress'))

@bp.route('/delete/service/<service_name>', methods=['POST'])
def delete_service(service_name):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    api_client = client.ApiClient()
    v1 = client.CoreV1Api(api_client)
    apps_v1 = client.AppsV1Api(api_client)
    # Suppression du Deployment
    try:
        apps_v1.delete_namespaced_deployment(name=service_name, namespace=ns_name)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            flash(f"Erreur lors de la suppression du deployment : {e.reason}", "error")
    # Suppression du Service
    try:
        v1.delete_namespaced_service(name=service_name, namespace=ns_name)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            flash(f"Erreur lors de la suppression du service : {e.reason}", "error")
    # Suppression du PVC (si existe, convention nom pvc = <service_name>-pvc ou cas spécial)
    pvc_name = f"{service_name}-pvc"
    if service_name == "wordpress":
        pvc_name = "wp-pvc"
    elif service_name == "postgres-service":
        pvc_name = "postgres-pvc"
    elif service_name == "minio":
        pvc_name = "s3-pvc"
    try:
        v1.delete_namespaced_persistent_volume_claim(name=pvc_name, namespace=ns_name)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            flash(f"Erreur lors de la suppression du PVC ({pvc_name}): {e.reason}", "error")
    flash(f"Service {service_name} et ses ressources ont été supprimés.", "success")
    return redirect(url_for('routes.services'))

@bp.route('/logs/service/<pod_name>', methods=['POST'])
def logs_service(pod_name):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    api_client = client.ApiClient()
    v1 = client.CoreV1Api(api_client)
    try:
        logs = v1.read_namespaced_pod_log(name=pod_name, namespace=ns_name, tail_lines=100)
    except Exception as e:
        logs = f"Erreur lors de la récupération des logs : {str(e)}"
    return render_template('dashboard/logs.html', pod_name=pod_name, logs=logs)

@bp.route('/connect_wordpress_postgres', methods=['POST'])
def connect_wordpress_postgres():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    username = session['user_id']
    ns_name = f"user-{username}"

    # Ici, on suppose que les credentials sont ceux par défaut ou récupérés d'une source fiable
    postgres_db = 'wordpress'
    postgres_user = 'wpuser'
    postgres_password = 'wppass'
    postgres_host = 'postgres-service'

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    api_client = client.ApiClient()
    apps_v1 = client.AppsV1Api(api_client)

    # Récupérer le déploiement WordPress
    deployment = apps_v1.read_namespaced_deployment(name="wordpress", namespace=ns_name)
    # Mettre à jour les variables d'environnement
    env = [
        client.V1EnvVar(name="WORDPRESS_DB_HOST", value=postgres_host),
        client.V1EnvVar(name="WORDPRESS_DB_USER", value=postgres_user),
        client.V1EnvVar(name="WORDPRESS_DB_PASSWORD", value=postgres_password),
        client.V1EnvVar(name="WORDPRESS_DB_NAME", value=postgres_db),
    ]
    deployment.spec.template.spec.containers[0].env = env
    # Appliquer la modification
    apps_v1.patch_namespaced_deployment(name="wordpress", namespace=ns_name, body=deployment)
    # Forcer le redémarrage du pod WordPress
    apps_v1.patch_namespaced_deployment(
        name="wordpress",
        namespace=ns_name,
        body={"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": datetime.datetime.utcnow().isoformat()}}}}}
    )
    flash("WordPress a été connecté à PostgreSQL et redémarré !", "success")
    return redirect(url_for('routes.dashboard')) 