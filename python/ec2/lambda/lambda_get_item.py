import json
import boto3

dynamodb = boto3.client('dynamodb')

def lambda_handler(event, context):
    body = event.get("body")
    try:
        data = json.loads(body)
        key1 = data.get("key1")
        # Usa la constante my_topic directamente
        my_topic = str(key1)
        
        # Consulta para obtener el elemento
        response = dynamodb.get_item(
            TableName='table_class_v3',
            Key={
                'id_curso': {
                    'S': my_topic
                }
            }
        )
        
        # Verifica si se encontró el elemento
        if 'Item' in response:
            return {
                'statusCode': 200,
                'body': json.dumps(response['Item'])
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Item not found'})
            }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
