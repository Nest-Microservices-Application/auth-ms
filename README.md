# 🔐 Auth Microservice

> [!IMPORTANT]
> If this project is running **individually**, without the `products-launcher`, ensure that the NATS server is running and properly configured. The `client-gateway` communicates with this microservice via the NATS server, which acts as a middleman and connects all microservices.

## 📦 Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/Nest-Microservices-Application/auth-ms
    cd auth-ms
    ```

2. **Install dependencies:**

    ```sh
    npm install
    ```

3. **Configure environment variables:**

    Copy the `.env.template` to `.env` and update the environment variables as needed.

## 🛠️ Development Setup

To start the development environment, follow these steps:

1. **Run Prisma migrations:**

    ```sh
    npx prisma migrate dev
    ```

2. **Start the development server:**

    ```sh
    npm run start:dev
    ```
