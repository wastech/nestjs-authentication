import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import validator from 'validator';

@Schema()
export class User extends Document {
  @Prop({
    required: true,
    validate: {
      validator: (value: string) => validator.isEmail(value),
      message: 'Invalid email',
    },
  })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ required: true })
  name: string;

  @Prop()
  date_of_birth: Date;

  @Prop()
  age: number;

  @Prop()
  sex: string;

  @Prop()
  avatar: string;

  @Prop({ default: Date.now })
  timestamp: Date;
}

export const AuthSchema = SchemaFactory.createForClass(User);
