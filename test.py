import asyncio

async def test_middleware():
    reader, writer = await asyncio.open_connection('127.0.0.1', 1389)
    
    # Solicitud de actualización
    request = "update;cn=testuser,dc=example,dc=com;sn;new_value"
    writer.write(request.encode())
    await writer.drain()
    
    # Leer respuesta
    response = await reader.read(1024)
    print(f"Response: {response.decode()}")
    
    writer.close()
    await writer.wait_closed()

asyncio.run(test_middleware())
