# Image alpine plus légère et sécurisée
FROM node:22-alpine

WORKDIR /app

# Copier uniquement les fichiers nécessaires
COPY src/package*.json ./

# Installer uniquement les dépendances production
RUN npm ci --only=production && npm cache clean --force

COPY src/ ./

# Créer un utilisateur non-root
RUN addgroup -S nodejs && adduser -S nodejs -G nodejs

USER nodejs

EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "server.js"]