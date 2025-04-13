import { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  DataGrid, 
  GridActionsCellItem,
  GridToolbar 
} from '@mui/x-data-grid';
import { 
  Box, 
  Typography, 
  Button, 
  Dialog, 
  DialogTitle, 
  DialogContent, 
  DialogActions,
  TextField,
  Snackbar,
  Alert
} from '@mui/material';
import { 
  Delete as DeleteIcon, 
  Edit as EditIcon,
  Add as AddIcon
} from '@mui/icons-material';

export default function Users() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [openDialog, setOpenDialog] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await axios.get('/api/admin/users');
      setUsers(res.data);
      setLoading(false);
    } catch (err) {
      showSnackbar('Failed to fetch users', 'error');
    }
  };

  const handleDelete = async (id) => {
    try {
      await axios.delete(`/api/admin/users/${id}`);
      fetchUsers();
      showSnackbar('User deleted successfully', 'success');
    } catch (err) {
      showSnackbar('Failed to delete user', 'error');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (currentUser?.id) {
        // Update existing user
        await axios.put(`/api/admin/users/${currentUser.id}`, currentUser);
        showSnackbar('User updated successfully', 'success');
      } else {
        // Create new user
        await axios.post('/api/admin/users', currentUser);
        showSnackbar('User created successfully', 'success');
      }
      setOpenDialog(false);
      fetchUsers();
    } catch (err) {
      showSnackbar(err.response?.data?.message || 'Operation failed', 'error');
    }
  };

  const showSnackbar = (message, severity) => {
    setSnackbar({ open: true, message, severity });
  };

  const columns = [
    { field: 'id', headerName: 'ID', width: 70 },
    { field: 'name', headerName: 'Name', width: 150 },
    { field: 'email', headerName: 'Email', width: 200 },
    { 
      field: 'createdAt', 
      headerName: 'Registered', 
      width: 180,
      valueGetter: (params) => new Date(params.value).toLocaleString()
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: 'Actions',
      width: 100,
      getActions: (params) => [
        <GridActionsCellItem
          icon={<EditIcon />}
          label="Edit"
          onClick={() => {
            setCurrentUser(params.row);
            setOpenDialog(true);
          }}
        />,
        <GridActionsCellItem
          icon={<DeleteIcon />}
          label="Delete"
          onClick={() => handleDelete(params.id)}
        />,
      ],
    },
  ];

  return (
    <Box sx={{ height: 600, width: '100%', p: 2 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
        <Typography variant="h4">User Management</Typography>
        <Button 
          variant="contained" 
          startIcon={<AddIcon />}
          onClick={() => {
            setCurrentUser({ name: '', email: '', password: '' });
            setOpenDialog(true);
          }}
        >
          Add User
        </Button>
      </Box>

      <DataGrid
        rows={users}
        columns={columns}
        loading={loading}
        components={{ Toolbar: GridToolbar }}
        pageSize={10}
        rowsPerPageOptions={[10, 25, 50]}
      />

      <Dialog open={openDialog} onClose={() => setOpenDialog(false)}>
        <DialogTitle>{currentUser?.id ? 'Edit User' : 'Add User'}</DialogTitle>
        <DialogContent>
          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 1 }}>
            <TextField
              margin="normal"
              fullWidth
              label="Name"
              value={currentUser?.name || ''}
              onChange={(e) => setCurrentUser({...currentUser, name: e.target.value})}
              required
            />
            <TextField
              margin="normal"
              fullWidth
              label="Email"
              type="email"
              value={currentUser?.email || ''}
              onChange={(e) => setCurrentUser({...currentUser, email: e.target.value})}
              required
            />
            <TextField
              margin="normal"
              fullWidth
              label={currentUser?.id ? 'New Password (leave blank to keep current)' : 'Password'}
              type="password"
              value={currentUser?.password || ''}
              onChange={(e) => setCurrentUser({...currentUser, password: e.target.value})}
              required={!currentUser?.id}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button onClick={handleSubmit} variant="contained">
            {currentUser?.id ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({...snackbar, open: false})}
      >
        <Alert severity={snackbar.severity}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}