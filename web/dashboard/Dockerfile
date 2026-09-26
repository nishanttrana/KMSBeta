FROM vecta-local/node:24.21.0-alpine AS build

WORKDIR /app
ENV npm_config_fetch_retries=5 \
    npm_config_fetch_retry_mintimeout=2000 \
    npm_config_fetch_retry_maxtimeout=20000 \
    npm_config_audit=false \
    npm_config_fund=false

COPY package*.json ./
RUN sh -ec 'for attempt in 1 2 3 4 5; do npm ci --prefer-offline && exit 0; sleep $((attempt * 2)); done; exit 1'

COPY . .
ARG VECTA_VERSION=dev
ARG VECTA_COMMIT=unknown
ARG VECTA_BUILD_TIME=unknown
ENV VITE_VERSION=${VECTA_VERSION} \
    VITE_COMMIT=${VECTA_COMMIT} \
    VITE_BUILD_TIME=${VECTA_BUILD_TIME}
RUN npm run build:docker

FROM vecta-local/nginx:1.30.5-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --chmod=0755 tls-watch.sh /docker-entrypoint.d/40-tls-watch.sh
COPY --from=build /app/dist /usr/share/nginx/html

# Drop root: grant the built-in nginx user ownership of runtime write paths,
# then switch to that user so the process never runs as UID 0.
RUN chown -R nginx:nginx /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 5173
