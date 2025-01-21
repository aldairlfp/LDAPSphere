import os
import asyncio
from fastapi import FastAPI, Request, HTTPException
from multiprocessing import Process
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi.responses import JSONResponse

from middleware.server import LDAPMiddleware
from middleware.request_handler import LDAPRequestHandler
from middleware.coordinator import MiddlewareCoordinator

# Cargar variables de entorno
load_dotenv()

# Crear aplicación FastAPI
app = FastAPI()

# Inicializar el coordinador y el handler como estados globales
coordinator = None
handler = None


# Modelos para solicitudes
class RegisterReplicaRequest(BaseModel):
    replica_address: str


class ReplicateRequest(BaseModel):
    operation: str
    data: dict


@app.post("/register_replica")
async def register_replica(request: RegisterReplicaRequest):
    """Registra una nueva réplica en el clúster."""
    if coordinator and coordinator.is_leader:
        coordinator.add_replica(request.replica_address)
        return JSONResponse(
            {"status": "success", "message": "Réplica registrada"}, status_code=200
        )
    raise HTTPException(status_code=403, detail="No soy el líder")


@app.post("/replicate")
async def replicate(request: ReplicateRequest):
    """Replica una operación (add o delete) en el servidor."""
    if not handler:
        raise HTTPException(status_code=500, detail="Handler no inicializado")

    try:
        operation = request.operation
        operation_data = request.data

        if operation == "add":
            dn = operation_data["dn"]
            attributes = operation_data["attributes"]
            if handler.add_entry(dn, attributes):
                print(f"Operación ADD replicada: {dn}")
                return JSONResponse(
                    {"status": "success", "message": "Operación ADD replicada"},
                    status_code=200,
                )
        elif operation == "delete":
            dn = operation_data["dn"]
            if handler.delete_entry(dn):
                print(f"Operación DELETE replicada: {dn}")
                return JSONResponse(
                    {"status": "success", "message": "Operación DELETE replicada"},
                    status_code=200,
                )
        else:
            raise HTTPException(status_code=400, detail="Operación no soportada")
    except Exception as e:
        print(f"Error procesando operación replicada: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    """Verifica el estado del servidor."""
    if coordinator:
        return JSONResponse(
            {
                "status": "ok",
                "role": "leader" if coordinator.is_leader else "replica",
                "address": coordinator.my_address,
                "replicas": coordinator.get_replicas(),
            },
            status_code=200,
        )
    raise HTTPException(status_code=500, detail="Coordinador no inicializado")


# Inicia FastAPI en un proceso separado
def run_fastapi():
    global coordinator, handler
    dns_name = os.getenv("DNS_NAME", "example.com")
    # coordinator = MiddlewareCoordinator(dns_name)

    # handler = LDAPRequestHandler(
    #     ldap_url=os.getenv("LDAP_URL"),
    #     admin_dn=os.getenv("LDAP_ADMIN_DN"),
    #     admin_password=os.getenv("LDAP_ADMIN_PASSWORD"),
    # )

    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)


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
    # Inicializar el coordinador antes de FastAPI
    dns_name = os.getenv("DNS_NAME", "example.com")

    # Inicia FastAPI en un proceso separado
    fastapi_process = Process(target=run_fastapi)
    fastapi_process.start()

    try:
        # Inicia el middleware principal
        run_middleware()
    finally:
        # Detiene FastAPI al finalizar
        fastapi_process.terminate()
