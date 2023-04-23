import {
  IsEmail,
  IsNotEmpty,
  IsDateString,
  IsString,
  IsOptional,
} from 'class-validator';

export class CreateAuthDto {
  @IsEmail({}, { message: 'Email must be a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @IsString()
  @IsNotEmpty({ message: 'Name is required' })
  name: string;

  @IsDateString()
  @IsNotEmpty({ message: 'Date of birth is required' })
  date_of_birth: Date;

  @IsString()
  @IsNotEmpty({ message: 'Sex is required' })
  sex: string;

  @IsOptional()
  @IsString()
  avatar?: string;
}
