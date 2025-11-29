import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Login = () => {
  const { login, loading, error, setError, keyStatus } = useAuth();
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [localError, setLocalError] = useState('');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    setLocalError('');
    setError(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const { username, password } = formData;

    if (!username || !password) {
      setLocalError('Username and password are required');
      return;
    }

    try {
      await login({ username, password });
    } catch {
      // error is handled in context
    }
  };

  return (
    <div className="page-container">
      <div className="card">
        <h1>Sign In</h1>
        {(localError || error) && <div className="error-text">{localError || error}</div>}
        {keyStatus && <div className="helper-text">{keyStatus}</div>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              name="username"
              type="text"
              value={formData.username}
              onChange={handleChange}
              autoComplete="username"
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              value={formData.password}
              onChange={handleChange}
              autoComplete="current-password"
            />
          </div>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        <div className="helper-text">
          Need an account? <Link to="/register">Register</Link>
        </div>
      </div>
    </div>
  );
};

export default Login;

