FROM python:3.6
MAINTAINER Chris Vantine "cav9225@rit.edu"

COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN wget https://bootstrap.pypa.io/get-pip.py
RUN pip install -r requirements.txt

COPY . /app

ENTRYPOINT ["python"]
CMD ["portcullis.py"]
