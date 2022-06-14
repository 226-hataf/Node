FROM python:3.9.11-slim

ENV APP_HOME /app
COPY ./src $APP_HOME

WORKDIR $APP_HOME

ADD jsc-chatbot-sa.json $APP_HOME
# ADD requirements $APP_HOME
RUN apt-get -qq update
RUN apt-get -qq -y install curl

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -

RUN cd $APP_HOME
RUN $HOME/.poetry/bin/poetry install 

ENV PORT=8080
ENV UVICORN_DEBUG=True
ENV AUTH_PROVIDER=firebase
ENV PYTHONPATH=$APP_HOME
ENV API_VERSION=0.1

ENV GOOGLE_APPLICATION_CREDENTIALS=$APP_HOME/jsc-chatbot-sa.json

CMD exec uvicorn --host 0.0.0.0 --port $PORT --workers 4 api:app