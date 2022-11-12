import 'source-map-support/register';
import { APIGatewayProxyEvent, APIGatewayProxyResult, APIGatewayProxyHandler } from 'aws-lambda';
import { generateUploadUrl,updateTodoUrl } from '../../businessLogic/todos';
import { getUserId } from '../utils';

export const handler: APIGatewayProxyHandler = 
  async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const todoId = event.pathParameters.todoId;
    const token = getUserId(event)

    const URL = await generateUploadUrl(todoId);
    await updateTodoUrl(token,todoId);
    return {
        statusCode: 202,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true
        },
        body: JSON.stringify({
            uploadUrl: URL,
        })
    };
};