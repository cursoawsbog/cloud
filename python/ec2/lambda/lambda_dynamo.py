import json
import boto3
import uuid

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('table_class_v3')

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))
    
    # Inicializa el response con un estado de error por defecto
    response = {
        "statusCode": 500,
        "body": json.dumps({"message": "Internal server error"})
    }
    
    body = event.get("body")
    if body:
        try:
            data = json.loads(body)
            key1 = data.get("key1")
            key2 = data.get("key2")

            # Procesar los datos
            response_message = f"Received key1: {key1}, key2: {key2}"

            # Generar un UUID
            dato = str(uuid.uuid4())

            # Intentar escribir en DynamoDB
            table.put_item(
                Item={
                    'id_curso': key1,
                    'username': key2,
                    'first_name': 'Jane',
                    'last_name': 'Doe',
                    'age': 25,
                    'account_type': 'standard_user',
                    'uuid': dato
                }
            )

            # Si la escritura es exitosa, actualizar el response
            response = {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "¡Datos escritos en DynamoDB!",
                    "dato": dato
                })
            }

        except json.JSONDecodeError:
            response = {
                "statusCode": 400,
                "body": json.dumps({"message": "Invalid JSON format"})
            }
        except Exception as e:
            print(f"Error writing to DynamoDB: {e}")
            response = {
                "statusCode": 500,
                "body": json.dumps({"message": "Error writing to DynamoDB"})
            }
    else:
        response = {
            "statusCode": 400,
            "body": json.dumps({"message": "Missing request body"})
        }
    
    return response
