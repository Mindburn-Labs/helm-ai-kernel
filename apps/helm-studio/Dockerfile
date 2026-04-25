# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Cache dependencies for the canonical Studio shell and shared tokens
COPY tsconfig.base.json ./tsconfig.base.json
COPY packages/design-tokens ./packages/design-tokens
COPY apps/helm-studio/package.json apps/helm-studio/package-lock.json ./apps/helm-studio/
WORKDIR /app/apps/helm-studio
RUN npm pkg set dependencies.@helm/design-tokens='file:../../packages/design-tokens' \
  && npm install

# Copy source
WORKDIR /app
COPY apps/helm-studio apps/helm-studio
COPY packages/design-tokens packages/design-tokens

# Build
WORKDIR /app/apps/helm-studio
RUN npm run build

# Stage 2: Serve
FROM nginx:alpine

# Copy build artifacts
COPY --from=builder /app/apps/helm-studio/dist /usr/share/nginx/html

# Copy custom nginx config for SPA fallback
COPY apps/helm-studio/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
