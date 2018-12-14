FROM python:3.6

COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt

COPY . /app
WORKDIR /app/portcullis

EXPOSE 80
ENTRYPOINT ["gunicorn"]
CMD ["-w 4", "-b", "0.0.0.0:80", "portcullis:app"]
