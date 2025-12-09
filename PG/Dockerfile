# Use a lightweight Python base image (Slim version for IoT vibes)
FROM python:3.9-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies (minimal)
# psutil needs gcc on some alpine images, but slim is fine
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements (if you have them) or install manually
# We perform manual install to keep image small and focused
RUN pip install --no-cache-dir \
    numpy \
    pandas \
    scikit-learn \
    joblib \
    psutil

# Copy your scripts and outputs
# Assumes your terminal context is the 'PG' folder
COPY scripts/ /app/scripts/
COPY outputs/endsem/ /app/outputs/endsem/

# Environment Variables for Python (unbuffered logs)
ENV PYTHONUNBUFFERED=1

# Run the router app
CMD ["python", "scripts/flow_aggregated_router_sim.py"]