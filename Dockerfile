FROM python:3.13-alpine

ARG APP_UID=20211
ARG APP_GID=20211

RUN addgroup -g "${APP_GID}" reporter \
    && adduser -D -H -u "${APP_UID}" -G reporter reporter

WORKDIR /app

COPY --chown=${APP_UID}:${APP_GID} src/ /app/src/

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER ${APP_UID}:${APP_GID}

EXPOSE 8080

CMD ["python", "-m", "dns_reporter.server"]
