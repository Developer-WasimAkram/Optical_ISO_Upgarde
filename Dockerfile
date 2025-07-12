FROM python:3.12.7-slim-bookworm

#Set the working directory

WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application files
COPY . .

# Expose Flask's default port
EXPOSE 5000

# Set environment variables for Flask (optional)
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Run the Flask app
CMD ["flask", "run"]


