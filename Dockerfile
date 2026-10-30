FROM node:20-bookworm-slim

WORKDIR /app

# Copiar manifiestos e instalar dependencias (usa binarios precompilados de sqlite3 para Linux)
COPY package.json package-lock.json* ./
RUN npm install

# Copiar el código fuente y la interfaz web
COPY tsconfig.json ./
COPY src ./src
COPY public ./public

EXPOSE 3000

# Fuerza salida con color en los logs del contenedor
ENV FORCE_COLOR=1

CMD ["npm", "start"]
