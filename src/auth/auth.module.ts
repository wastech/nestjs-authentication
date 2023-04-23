import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthService } from './auth.service';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { User, AuthSchema } from './entities/auth.entity';
import { JwtModule } from '@nestjs/jwt';
import { AuthGuard } from './auth.guard';
import { RolesGuard } from './roles.guard';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: AuthSchema }]),
    JwtModule.register({
      global: true,
      secret: process.env.SECRET,
      signOptions: { expiresIn: process.env.JWT_EXPIRING_DATE },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AuthModule {}
