import {
  Injectable,
  HttpException,
  HttpStatus,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './entities/auth.entity';
import * as bcrypt from 'bcrypt';
// import * as jwt from 'jsonwebtoken';
import { Role } from './entities/auth.entity';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async register(createAuthDto: CreateAuthDto) {
    const { email, password, name, sex, date_of_birth } = createAuthDto;

    if (!email || !password || !name || !sex || !date_of_birth) {
      throw new Error('Missing required fields');
    }

    // Check if user already exists
    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create user
    const user = await this.userModel.create({
      email,
      password: hashedPassword,
      name,
      sex,
      date_of_birth,
    });
    return user;
  }

  async getUserByEmail(email: string): Promise<User> {
    return this.userModel.findOne({ email: email });
  }

  async validateUser(email: string, password: string): Promise<User> {
    const user = await this.userModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }

  async login(user: User) {
    const payload = { email: user.email, sub: user.id };

    const token = await this.jwtService.signAsync(payload, {
      secret: process.env.SECRET,
      expiresIn: process.env.JWT_EXPIRING_DATE, // Set the expiration time to 1 hour
    });

    return {
      token,
      user,
    };
  }

  async validateToken(token: string) {
    try {
      const decoded = this.jwtService.verify(token);
      const user = await this.userModel.findById(decoded.sub);
      if (!user) {
        throw new UnauthorizedException();
      }
      return user;
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  async findById(_id: number): Promise<User> {
    const user = await this.userModel.findById(_id);
    return user;
  }

  async updateUser(
    userId: string,
    updateUserDto: UpdateAuthDto,
  ): Promise<User> {
    const allowedUpdates = ['name', 'email']; // fields that can be updated
    const updates = Object.keys(updateUserDto); // fields sent in the request body
    const isValidUpdate = updates.every((update) =>
      allowedUpdates.includes(update),
    ); // check if all fields are allowed to be updated

    if (!isValidUpdate) {
      throw new BadRequestException('Invalid updates!');
    }

    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('User not found!');
    }

    updates.forEach((update) => {
      user[update] = updateUserDto[update];
    });

    await user.save();

    return user;
  }

  async findAll(): Promise<User[]> {
    return this.userModel.find().exec();
  }

  async updateUserPassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ): Promise<User> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      // throw new Error(`User with id ${userId} not found`);
      // User does not exist
      throw new NotFoundException(`User with id ${userId} not found`);
    }
    // Check if the current user is authorized to update the password
    // Check if the old password matches the user's current password
    const oldPasswordMatches = await bcrypt.compare(oldPassword, user.password);

    if (!oldPasswordMatches) {
      // Old password does not match
      throw new UnauthorizedException('Invalid old password');
    }
    if (oldPassword === newPassword) {
      throw new BadRequestException(
        'New password cannot be the same as old password',
      );
    }

    // Hash the new password using bcrypt and update it in the database
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updatedUser = await this.userModel.findByIdAndUpdate(
      userId,
      { password: hashedNewPassword },
      { new: true },
    );

    return updatedUser;
  }

  async deleteUser(userId: string, userRole: Role): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user is authorized to delete
    if (userRole !== Role.Admin && user._id.toString() !== userId) {
      throw new UnauthorizedException(
        'You are not authorized to delete this user',
      );
    }

    return this.userModel.findByIdAndRemove(userId);
  }

  async getUser(id: string): Promise<User> {
    const user = await this.userModel.findById(id).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findOneByEmail(email: string): Promise<User | null> {
    return this.userModel.findOne({ email }).exec();
  }

  async findOneByResetToken(token: string): Promise<User | null> {
    return this.userModel.findOne({ resetPasswordToken: token }).exec();
  }

  async save(user: User): Promise<User> {
    const UserModel = new this.userModel(user);
    return UserModel.save();
  }

  generateResetToken(): string {
    return randomBytes(20).toString('hex');
  }

  async sendPasswordResetEmail(
    email: string,
    resetToken: string,
  ): Promise<void> {
    const transporter = nodemailer.createTransport({
      // configure nodemailer transport options here
    });
    await transporter.sendMail({
      from: 'your-email@example.com',
      to: email,
      subject: 'Password reset',
      html: `Hello,<br><br>We received a request to reset your password. If this was you, please follow the link below to reset your password:<br><br><a href="http://example.com/reset-password/${resetToken}">Reset password</a><br><br>If you did not request a password reset, please ignore this email.<br><br>Best regards,<br>The Example Team`,
    });
  }
}
