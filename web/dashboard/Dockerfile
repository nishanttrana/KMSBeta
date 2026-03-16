FROM vecta-local/node:20-alpine AS build

WORKDIR /app
ENV npm_config_fetch_retries=5 \
    npm_config_fetch_retry_mintimeout=2000 \
    npm_config_fetch_retry_maxtimeout=20000 \
    npm_config_audit=false \
    npm_config_fund=false

COPY package*.json ./
RUN sh -ec 'for attempt in 1 2 3 4 5; do npm ci --prefer-offline && exit 0; sleep $((attempt * 2)); done; exit 1'

COPY . .
RUN npm run build:docker

FROM vecta-local/nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 5173
