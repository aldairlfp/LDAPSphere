import os
import asyncio
from flask import Flask, request, jsonify
from multiprocessing import Process
from dotenv import load_dotenv

from middleware.server import LDAPMiddleware
from middleware.request_handler import LDAPRequestHandler
from middleware.coordinator import MiddlewareCoordinator

# Cargar variables de entorno
load_dotenv()

# Servidor Flask para recibir réplicas
app = Flask(__name__)

# Inicializar el coordinador y el handler en el objeto Flask
app.config["COORDINATOR"] = None
app.config["HANDLER"] = None


@app.route("/register_replica", methods=["POST"])
def register_replica():
    data = request.get_json()
    replica_address = data.get("replica_address")
    coordinator = app.config["COORDINATOR"]
    if coordinator and coordinator.is_leader:
        coordinator.add_replica(replica_address)
        return jsonify({"status": "success", "message": "Réplica registrada"}), 200
    return jsonify({"status": "error", "message": "No soy el líder"}), 403


@app.route("/replicate", methods=["POST"])
def replicate():
    data = request.get_json()
    operation = data.get("operation")
    operation_data = data.get("data")

    handler = app.config["HANDLER"]

    if not operation or not operation_data:
        return (
            jsonify({"status": "error", "message": "Datos de operación faltantes"}),
            400,
        )

    try:
        if operation == "add":
            dn = operation_data["dn"]
            attributes = operation_data["attributes"]
            if handler.add_entry(dn, attributes):
                print(f"Operación ADD replicada: {dn}")
                return (
                    jsonify(
                        {"status": "success", "message": "Operación ADD replicada"}
                    ),
                    200,
                )
        elif operation == "delete":
            dn = operation_data["dn"]
            if handler.delete_entry(dn):
                print(f"Operación DELETE replicada: {dn}")
                return (
                    jsonify(
                        {"status": "success", "message": "Operación DELETE replicada"}
                    ),
                    200,
                )
        else:
            return (
                jsonify({"status": "error", "message": "Operación no soportada"}),
                400,
            )
    except Exception as e:
        print(f"Error procesando operación replicada: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    coordinator = app.config["COORDINATOR"]
    if coordinator:
        return (
            jsonify(
                {
                    "status": "ok",
                    "role": "leader" if coordinator.is_leader else "replica",
                    "address": coordinator.my_address,
                    "replicas": coordinator.get_replicas(),
                }
            ),
            200,
        )
    else:
        return (
            jsonify({"status": "error", "message": "Coordinador no inicializado"}),
            500,
        )


# Inicia Flask en un proceso separado
def run_flask():
    dns_name = os.getenv("DNS_NAME", "example.com")
    app.config["COORDINATOR"] = MiddlewareCoordinator(dns_name)

    app.config["HANDLER"] = LDAPRequestHandler(
        ldap_url=os.getenv("LDAP_URL"),
        admin_dn=os.getenv("LDAP_ADMIN_DN"),
        admin_password=os.getenv("LDAP_ADMIN_PASSWORD"),
    )

    app.run(host="0.0.0.0", port=5000)


# Función principal del middleware
def run_middleware():
    dns_name = os.getenv("DNS_NAME", "example.com")
    coordinator = MiddlewareCoordinator(dns_name)

    handler = LDAPRequestHandler(
        ldap_url=os.getenv("LDAP_URL"),
        admin_dn=os.getenv("LDAP_ADMIN_DN"),
        admin_password=os.getenv("LDAP_ADMIN_PASSWORD"),
    )

    middleware = LDAPMiddleware(coordinator, handler)  # Pasar coordinator y handler
    asyncio.run(middleware.run("0.0.0.0", int(os.getenv("PORT", 1389))))


if __name__ == "__main__":
    # Inicializar el coordinador antes de Flask
    dns_name = os.getenv("DNS_NAME", "example.com")

    # Inicia Flask en un proceso separado
    flask_process = Process(target=run_flask)
    flask_process.start()

    try:
        # Inicia el middleware principal
        run_middleware()
    finally:
        # Detiene Flask al finalizar
        flask_process.terminate()
