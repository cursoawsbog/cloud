import json
import logging

# Configura el logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # Log de la petición de entrada
    logger.info(f"Entrada: {json.dumps(event)}")

    response = {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda v2! deploy 2.0')
    }

    # Log de la respuesta de salida
    logger.info(f"Salida: {json.dumps(response)}")

    return response