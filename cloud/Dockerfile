# Utiliser une image Python officielle comme base
FROM python:3.9-slim

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier les fichiers de dépendances et les installer
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
RUN pip install --no-cache-dir "gunicorn>=20.1.0"

# Copier le reste du code de l'application dans le conteneur
COPY . .

# Exposer le port sur lequel l'application tournera
EXPOSE 5000

# Commande pour lancer l'application avec Gunicorn (serveur de production)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "wsgi:app"] 