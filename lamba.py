import json

# Define a list of malicious or disallowed file types
DISALLOWED_EXTENSIONS = ['.exe', '.bat', '.sh', '.js', '.vbs', '.jar', '.php', '.py']

def lambda_handler(event, context):
    try:
        print("S3 Event Received:")
        print(json.dumps(event, indent=2))

        for record in event['Records']:
            bucket_name = record['s3']['bucket']['name']
            file_name = record['s3']['object']['key']

            # Check for potentially malicious file extensions
            if any(file_name.lower().endswith(ext) for ext in DISALLOWED_EXTENSIONS):
                print(f"Warning: File '{file_name}' in bucket '{bucket_name}' has a potentially malicious extension.")
                
               
                import boto3
                s3 = boto3.client('s3')
                s3.delete_object(Bucket=bucket_name, Key=file_name)
                print(f"File '{file_name}' deleted from bucket '{bucket_name}'.")
                
            else:
                print(f"File '{file_name}' uploaded to bucket '{bucket_name}' is safe.")

        return {
            "statusCode": 200,
            "body": json.dumps("File upload processed successfully!")
        }

    except Exception as e:
        print(f"Error processing S3 event: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps("Error processing event.")
        }
