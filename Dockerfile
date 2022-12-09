FROM python:3.9.11-slim

ENV APP_HOME /app
COPY ./src $APP_HOME

WORKDIR $APP_HOME

# ADD jsc-chatbot-sa.json $APP_HOME
ADD requirements.txt $APP_HOME
# RUN apt-get -qq update
# RUN apt-get -qq -y install curl
RUN pip install psycopg2-binary
RUN pip3 install -r requirements.txt
# RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -

# RUN $HOME/.poetry/bin/poetry install 

ENV PORT=8080
ENV UVICORN_DEBUG=True
ENV PYTHONPATH=$APP_HOME

# ENV GOOGLE_APPLICATION_CREDENTIALS=$APP_HOME/jsc-chatbot-sa.json

CMD exec uvicorn --host 0.0.0.0 --port $PORT --workers 4 api:app