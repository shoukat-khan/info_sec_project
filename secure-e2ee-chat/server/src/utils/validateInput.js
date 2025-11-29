const validateRegisterInput = (body) => {
  const { username, password, confirmPassword } = body;

  if (!username || !password || !confirmPassword) {
    return { valid: false, message: 'Username, password and confirm password are required' };
  }

  if (password !== confirmPassword) {
    return { valid: false, message: 'Passwords do not match' };
  }

  return { valid: true };
};

const validateLoginInput = (body) => {
  const { username, password } = body;

  if (!username || !password) {
    return { valid: false, message: 'Username and password are required' };
  }

  return { valid: true };
};

module.exports = {
  validateRegisterInput,
  validateLoginInput
};

