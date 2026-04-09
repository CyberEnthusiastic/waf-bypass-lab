# Generic Dockerfile for AI Security Projects
# Build:  docker build -t ai-sec-tool .
# Run:    docker run --rm -v "$(pwd)/target:/work/target" ai-sec-tool target/

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="AI Security Projects"
LABEL org.opencontainers.image.source="https://github.com/CyberEnthusiastic"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Adithya Vasamsetti <CyberEnthusiastic>"

# Create non-root user
RUN groupadd -r sec && useradd -r -g sec -m -d /home/sec sec

WORKDIR /app

# Install dependencies first (better Docker layer caching)
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && if [ -s requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# Copy the rest of the project
COPY . .

# Drop to non-root
RUN chown -R sec:sec /app
USER sec

# Most projects have a main .py that accepts a target dir
# Default to scanning /work (mount point) if no args given
ENTRYPOINT ["python"]
CMD ["--version"]
