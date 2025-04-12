import { useState, useEffect } from 'react';
import { View, Text, TextInput, Pressable, StyleSheet, Alert } from 'react-native';
import { Link, router } from 'expo-router';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login, signup } = useAuth();
  
  const defaultTestEmail = 'test@example.com';
  const defaultTestPassword = 'password123';

const handleLogin = async () => {
  try {
    await login(email, password);
    router.replace('/(tabs)');
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Invalid email or password';
    Alert.alert('Login Error', message);
  }
};

const useTestAccount = async () => {
  try {
    setEmail(defaultTestEmail);
    setPassword(defaultTestPassword);
    await login(defaultTestEmail, defaultTestPassword);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Test account login failed';
    Alert.alert('Error', message);
  }
};
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Login</Text>
      
      <TextInput
        style={styles.input}
        placeholder="Email"
        value={email}
        onChangeText={setEmail}
        placeholderTextColor="#999"
        autoCapitalize="none"
        keyboardType="email-address"
      />
      
      <TextInput
        style={styles.input}
        placeholder="Password"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        placeholderTextColor="#999"
      />
      
      <Pressable style={styles.button} onPress={handleLogin}>
        <Text style={styles.buttonText}>Login</Text>
      </Pressable>

      <Pressable style={styles.testButton} onPress={useTestAccount}>
        <Text style={styles.testButtonText}>Use Test Account</Text>
      </Pressable>
      
      <Link href="/singup" asChild>
        <Pressable>
          <Text style={styles.link}>Don't have an account? Sign Up</Text>
        </Pressable>
      </Link>
      
      <Text style={styles.testNote}>
        For testing: {defaultTestEmail} / {defaultTestPassword}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    padding: 20,
    backgroundColor: '#121212',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: 'white',
    marginBottom: 30,
    textAlign: 'center',
  },
  input: {
    backgroundColor: 'white',
    padding: 15,
    borderRadius: 8,
    marginBottom: 15,
    fontSize: 16,
  },
  button: {
    backgroundColor: '#2196F3',
    padding: 15,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 10,
  },
  buttonText: {
    color: 'white',
    fontWeight: 'bold',
    fontSize: 16,
  },
  testButton: {
    backgroundColor: '#555',
    padding: 10,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 10,
  },
  testButtonText: {
    color: 'white',
    fontSize: 14,
  },
  link: {
    color: '#2196F3',
    textAlign: 'center',
    marginTop: 20,
  },
  testNote: {
    color: '#888',
    fontSize: 12,
    textAlign: 'center',
    marginTop: 30,
    position: 'absolute',
    bottom: 20,
    alignSelf: 'center',
  }
});
