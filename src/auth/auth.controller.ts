import {
  Controller,
  Get,
  Post,
  Body,
  HttpException,
  UseGuards,
  NotFoundException,
  Put,
  Req,
  UseInterceptors,
  UploadedFile,
  Request,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Public } from './decorators/public.decorator';
import { RolesGuard } from './roles.guard';
import { Roles } from './decorators/roles.decorator';
import { Role } from './entities/auth.entity';
import { FileInterceptor } from '@nestjs/platform-express';
import { User } from './entities/auth.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get()
  @Roles(Role.Admin)
  async findAll(): Promise<User[]> {
    return this.authService.findAll();
  }

  @Public()
  @Post('register')
  async register(@Body() createAuthDto: CreateAuthDto) {
    const user = await this.authService.register(createAuthDto);
    return { user };
  }

  @Public()
  @Post('login')
  async login(@Body() user: CreateAuthDto) {
    const validatedUser = await this.authService.validateUser(
      user.email,
      user.password,
    );
    return this.authService.login(validatedUser);
  }

  @Post('verify')
  async verify(@Body() payload: { token: string }) {
    return this.authService.validateToken(payload.token);
  }

  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @Patch('update-password')
  async changePassword(
    @Body('oldPassword') oldPassword: string,
    @Body('newPassword') newPassword: string,
    @Request() req,
  ) {
    console.log(req.body);
    const userId = req.user.id;
    // Call the changePassword method on the AuthService
    const result = await this.authService.updateUserPassword(
      userId,
      oldPassword,
      newPassword,
    );

    return result;
  }

  @Put(':id')
  async updateUser(@Param('id') id: string, @Body() UpdateAuthDto: any) {
    const userId = id;

    return this.authService.updateUser(userId, UpdateAuthDto);
  }

  @Delete(':userId')
  @UseGuards(RolesGuard)
  @Roles(Role.Admin)
  async deleteUser(@Request() req, @Param('userId') userId: string) {
    const deletedUser = await this.authService.deleteUser(
      userId,
      req.user.role,
    );
    return {
      message: `User ${deletedUser.name} has been deleted successfully!`,
    };
  }

  @Get(':id') // Defines a new route with a dynamic parameter "id"
  @UseGuards(RolesGuard)
  @Roles(Role.Admin, Role.User) // Allows both admin and regular users to access this route
  async getUser(@Param('id') id: string): Promise<User> {
    return this.authService.getUser(id); // Calls the "getUser" method in the "AuthService" and returns the result
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.authService.findOneByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    const resetToken = this.authService.generateResetToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // Token expires in 1 hour
    await this.authService.save(user);
    await this.authService.sendPasswordResetEmail(user.email, resetToken);
    return { message: 'Password reset email sent' };
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    const { token, newPassword } = resetPasswordDto;
    const user = await this.authService.findOneByResetToken(token);
    if (!user) {
      throw new NotFoundException('Invalid or expired token');
    }
    if (user.resetPasswordExpires && user.resetPasswordExpires < new Date()) {
      throw new NotFoundException('Invalid or expired token');
    }
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await this.authService.save(user);
    return { message: 'Password reset successful' };
  }

  @Get('/users/:email')
  async getUserByEmail(@Param('email') email: string): Promise<User> {
    return this.authService.getUserByEmail(email);
  }
}
