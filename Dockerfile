FROM python:3.9.11-slim

ENV APP_HOME /app
WORKDIR $APP_HOME
COPY ./src $APP_HOME

RUN pip3 install -r requirements

ADD firebase_config.json $APP_HOME
ADD jsc-chatbot-sa.json $APP_HOME

ENV PORT=8080
ENV UVICORN_DEBUG=True
ENV AUTH_PROVIDER=firebase
ENV PYTHONATH=$APP_HOME
ENV API_VERSION=0.1

ENV GOOGLE_APPLICATION_CREDENTIALS=$APP_HOME/jsc-chatbot-sa.json

CMD exec gunicorn --bind :$PORT --workers 2 --threads 4 --timeout 0 api:app