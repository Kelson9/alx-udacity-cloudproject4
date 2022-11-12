import { TodoAccess} from '../dataLayer/todosAccess'
import {Todo} from '../models/todoItem'

import { CreateTodoRequest } from '../requests/CreateTodoRequest'

import {UpdateTodoRequest } from '../requests/UpdateTodoRequest'
import { parseUserId } from '../auth/utils';

const uuidv4 = require('uuid/v4');
const todoAccess = new TodoAccess();

export async function getAllTodos(jwtToken : string): Promise<Todo[]> {
  const userId = parseUserId(jwtToken);
  return todoAccess.getAllTodos(userId)
}

export async function createTodo(
  createTodoRequest: CreateTodoRequest,
  jwtToken: string
): Promise<Todo> { 
  const userId = parseUserId(jwtToken);
  const itemId = uuidv4();
  return await todoAccess.createTodo({
      todoId: itemId,
      userId,
      createdAt: new Date().toISOString(),
      done: false,
      ...createTodoRequest,
  })
}

export async function generateUploadUrl(todoId: string): Promise<string> {
  return todoAccess.generateUploadUrl(todoId);
  }
export async function updateTodo(
  jwtToken: string,
    todoId: string,
    updateTodoRequest : UpdateTodoRequest
  ): Promise<void> {

    const userId = parseUserId(jwtToken);
    await todoAccess.updateTodo(updateTodoRequest,userId,todoId)
  }

export async function updateTodoUrl( 
  jwtToken: string,
  todoId: string
) : Promise<void> {
  
  const userId = parseUserId(jwtToken);
  await todoAccess.updateUrl(userId,todoId)
}


export async function deleteTodo (todoId: string, jwtToken : string) : Promise<string> {
    const userId = parseUserId(jwtToken);
    return await todoAccess.deleteTodo(todoId,userId)
}