FROM python:3
WORKDIR /app
ENV FLASK_APP app/spell_check/app.py
ENV FLASK_RUN_HOST 0.0.0.0
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
EXPOSE 8080
COPY . .
CMD [ "flask", "run", "--host", "0.0.0.0" ]