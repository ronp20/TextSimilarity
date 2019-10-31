FROM python:3
WORKDIR /usr/src/app
COPY requirments.txt .
RUN pip install --no-cache-dir -r requirments.txt
COPY . .
RUN pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-2.2.0/en_core_web_sm-2.2.0.tar.gz
CMD ["python", "app.py"]
