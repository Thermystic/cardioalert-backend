import express from 'express';
import cors from 'cors';
import { config } from './config/env';
import prisma from './config/database';
import { hashPassword, comparePassword } from './utils/password';
import { generateToken, verifyToken } from './utils/jwt';
import { validateEmail, validatePassword, validatePhoneNumber } from './utils/validation';

const app = express();

app.use(cors());
app.use(express.json());

// Authentication middleware
const authenticate = (req: any, res: any, next: any) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token.' });
  }
};

// Role-based access control
const requireRole = (roles: string[]) => {
  return (req: any, res: any, next: any) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Access denied. User not authenticated.' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
    }

    next();
  };
};

// Health endpoints
app.get('/health', (req: any, res: any) => {
  res.json({ 
    status: 'OK', 
    message: 'CardioAlert Backend is running!',
    environment: config.nodeEnv
  });
});

app.get('/health/db', async (req: any, res: any) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'OK', message: 'Database connection successful' });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', message: 'Database connection failed' });
  }
});

// ========== AUTHENTICATION ENDPOINTS ==========

// Register endpoint
app.post('/api/auth/register', async (req: any, res: any) => {
  try {
    const { email, password, firstName, lastName, phone, role = 'PATIENT' } = req.body;

    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ message: 'Email, password, first name, and last name are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ message: passwordValidation.message });
    }

    if (phone && !validatePhoneNumber(phone)) {
      return res.status(400).json({ message: 'Invalid phone number format' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    const hashedPassword = await hashPassword(password);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstName,
        lastName,
        phone,
        role: role.toUpperCase(),
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        createdAt: true,
      },
    });

    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    res.status(201).json({
      message: 'User registered successfully',
      user,
      token,
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req: any, res: any) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (!user.isActive) {
      return res.status(401).json({ message: 'Account is deactivated' });
    }

    const isValidPassword = await comparePassword(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
      token,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ========== EMERGENCY ALERT ENDPOINTS ==========

// Create Emergency Alert (Patients only)
app.post('/api/alerts', authenticate, requireRole(['PATIENT']), async (req: any, res: any) => {
  try {
    const { type, severity, description, latitude, longitude, address } = req.body;

    // Validation
    if (!type || !severity || !latitude || !longitude) {
      return res.status(400).json({ 
        message: 'Alert type, severity, latitude, and longitude are required' 
      });
    }

    // Validate enums
    const validTypes = ['HEART_ATTACK', 'STROKE', 'FALL', 'BREATHING_DIFFICULTY', 'CHEST_PAIN', 'OTHER'];
    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

    if (!validTypes.includes(type)) {
      return res.status(400).json({ message: 'Invalid alert type' });
    }

    if (!validSeverities.includes(severity)) {
      return res.status(400).json({ message: 'Invalid severity level' });
    }

    // Check if user has an active alert already
    const existingAlert = await prisma.emergencyAlert.findFirst({
      where: {
        patientId: req.user.userId,
        status: 'ACTIVE'
      }
    });

    if (existingAlert) {
      return res.status(400).json({ 
        message: 'You already have an active emergency alert. Please wait for response or cancel it first.' 
      });
    }

    // Create the emergency alert
    const alert = await prisma.emergencyAlert.create({
      data: {
        patientId: req.user.userId,
        type,
        severity,
        description,
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        address,
        status: 'ACTIVE'
      },
      include: {
        patient: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            phone: true,
            email: true
          }
        }
      }
    });

    // TODO: Send real-time notifications to nearby responders
    console.log(`🚨 EMERGENCY ALERT CREATED: ${type} - ${severity} severity`);
    console.log(`📍 Location: ${latitude}, ${longitude}`);
    console.log(`👤 Patient: ${alert.patient.firstName} ${alert.patient.lastName}`);

    res.status(201).json({
      message: 'Emergency alert created successfully',
      alert
    });
  } catch (error) {
    console.error('Create alert error:', error);
    res.status(500).json({ message: 'Failed to create emergency alert' });
  }
});

// Get Alerts (Different views for patients vs responders)
app.get('/api/alerts', authenticate, async (req: any, res: any) => {
  try {
    let alerts;

    if (req.user.role === 'PATIENT') {
      // Patients see only their own alerts
      alerts = await prisma.emergencyAlert.findMany({
        where: { patientId: req.user.userId },
        orderBy: { createdAt: 'desc' },
        include: {
          responder: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              phone: true
            }
          }
        }
      });
    } else if (req.user.role === 'RESPONDER') {
      // Responders see active alerts they can respond to
      alerts = await prisma.emergencyAlert.findMany({
        where: { 
          status: { in: ['ACTIVE', 'RESPONDED'] },
          // Optionally filter by distance in the future
        },
        orderBy: [
          { severity: 'desc' }, // Critical first
          { createdAt: 'asc' }   // Oldest first
        ],
        include: {
          patient: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              phone: true
            }
          },
          responder: {
            select: {
              id: true,
              firstName: true,
              lastName: true
            }
          }
        }
      });
    } else {
      // Admins see all alerts
      alerts = await prisma.emergencyAlert.findMany({
        orderBy: { createdAt: 'desc' },
        include: {
          patient: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              phone: true,
              email: true
            }
          },
          responder: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              phone: true
            }
          }
        }
      });
    }

    res.json({ alerts });
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ message: 'Failed to retrieve alerts' });
  }
});

// Respond to Alert (Responders only)
app.put('/api/alerts/:id/respond', authenticate, requireRole(['RESPONDER']), async (req: any, res: any) => {
  try {
    const { id } = req.params;

    // Check if alert exists and is active
    const alert = await prisma.emergencyAlert.findUnique({
      where: { id },
      include: {
        patient: {
          select: {
            firstName: true,
            lastName: true,
            phone: true
          }
        }
      }
    });

    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    if (alert.status !== 'ACTIVE') {
      return res.status(400).json({ message: 'Alert is no longer active' });
    }

    if (alert.responderId) {
      return res.status(400).json({ message: 'Alert already has a responder' });
    }

    // Update alert with responder
    const updatedAlert = await prisma.emergencyAlert.update({
      where: { id },
      data: {
        responderId: req.user.userId,
        status: 'RESPONDED',
        respondedAt: new Date()
      },
      include: {
        patient: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            phone: true
          }
        },
        responder: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            phone: true
          }
        }
      }
    });

    console.log(`✅ RESPONDER ASSIGNED: ${req.user.email} responding to ${alert.type} alert`);

    res.json({
      message: 'Successfully assigned to emergency alert',
      alert: updatedAlert
    });
  } catch (error) {
    console.error('Respond to alert error:', error);
    res.status(500).json({ message: 'Failed to respond to alert' });
  }
});

// Update Alert Status
app.put('/api/alerts/:id/status', authenticate, async (req: any, res: any) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['ACTIVE', 'RESPONDED', 'RESOLVED', 'CANCELLED'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    // Check if alert exists
    const alert = await prisma.emergencyAlert.findUnique({
      where: { id }
    });

    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    // Authorization: patients can only update their own alerts, responders can update alerts they're assigned to
    if (req.user.role === 'PATIENT' && alert.patientId !== req.user.userId) {
      return res.status(403).json({ message: 'You can only update your own alerts' });
    }

    if (req.user.role === 'RESPONDER' && alert.responderId !== req.user.userId) {
      return res.status(403).json({ message: 'You can only update alerts you are assigned to' });
    }

    // Update the alert
    const updateData: any = { status };
    if (status === 'RESOLVED') {
      updateData.resolvedAt = new Date();
    }

    const updatedAlert = await prisma.emergencyAlert.update({
      where: { id },
      data: updateData,
      include: {
        patient: {
          select: {
            id: true,
            firstName: true,
            lastName: true
          }
        },
        responder: {
          select: {
            id: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });

    console.log(`📝 ALERT STATUS UPDATED: ${id} -> ${status}`);

    res.json({
      message: 'Alert status updated successfully',
      alert: updatedAlert
    });
  } catch (error) {
    console.error('Update alert status error:', error);
    res.status(500).json({ message: 'Failed to update alert status' });
  }
});

// ========== USER MANAGEMENT ==========

// Protected routes
app.get('/api/users', authenticate, async (req: any, res: any) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, email: true, firstName: true, lastName: true, role: true, isActive: true }
    });
    res.json({ users });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users' });
  }
});

app.listen(config.port, () => {
  console.log('🚀 CardioAlert Backend running on port ' + config.port);
  console.log('📍 Auth endpoints: http://localhost:' + config.port + '/api/auth');
  console.log('🚨 Alert endpoints: http://localhost:' + config.port + '/api/alerts');
  console.log('🔐 Protected endpoints require Authorization header');
});
