import os
import asyncio
from flask import Flask, request, jsonify
from multiprocessing import Process
from dotenv import load_dotenv

from middleware.server import LDAPMiddleware
from middleware.request_handler import LDAPRequestHandler

# Cargar variables de entorno
load_dotenv()

# Servidor Flask para recibir réplicas
app = Flask(__name__)


@app.route("/replicate", methods=["POST"])
def replicate_operation():
    data = request.get_json()
    print(f"Operación replicada recibida: {data}")
    try:
        handler = LDAPRequestHandler(
            ldap_url=os.getenv("LDAP_URL"),
            admin_dn=os.getenv("LDAP_ADMIN_DN"),
            admin_password=os.getenv("LDAP_ADMIN_PASSWORD"),
        )
        handler.handle_request(data)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Error procesando operación replicada: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# Función para correr Flask en un proceso separado
def run_flask():
    port = int(os.getenv("FLASK_PORT", 5000))  # Puerto predeterminado para Flask
    app.run(host="0.0.0.0", port=port)


# Función principal del middleware
def run_middleware():
    handler = LDAPRequestHandler(
        ldap_url=os.getenv("LDAP_URL"),
        admin_dn=os.getenv("LDAP_ADMIN_DN"),
        admin_password=os.getenv("LDAP_ADMIN_PASSWORD"),
    )

    middleware = LDAPMiddleware("middleware2.example.com", handler)
    asyncio.run(middleware.run("0.0.0.0", int(os.getenv("PORT", 1389))))


if __name__ == "__main__":
    # Inicia Flask en un proceso separado
    flask_process = Process(target=run_flask)
    flask_process.start()

    try:
        # Inicia el middleware principal
        run_middleware()
    finally:
        # Detiene Flask al finalizar
        flask_process.terminate()
