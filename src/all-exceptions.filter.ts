/* eslint-disable prettier/prettier */
import {
  Catch,
  ExceptionFilter,
  HttpException,
  ArgumentsHost,
} from '@nestjs/common';
import { Response } from 'express';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(error: Error, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = 500;
    const message = error.message || 'Internal server error';
    const exceptionResponse = { message };

    if (error instanceof HttpException) {
      response.status(error.getStatus()).json(exceptionResponse);
    } else {
      response.status(status).json(exceptionResponse);
    }
  }
}
