import FontAwesome from '@expo/vector-icons/FontAwesome';
import { Link, Tabs, Redirect } from 'expo-router';
import { Pressable, useColorScheme } from 'react-native';
import { useAuth } from '../../context/AuthContext';

import { Colors } from '../../constants/Colors';

export default function TabLayout() {
  const colorScheme = useColorScheme();
  const { user, logout } = useAuth();

  if (!user) {
    return <Redirect href="/login" />;
  }
  
  return (
    <Tabs
      screenOptions={{
        tabBarStyle: {
          backgroundColor: '#121212',
          borderTopColor: '#333',
        },
        tabBarActiveTintColor: '#FFFFFF',
        tabBarInactiveTintColor: '#AAAAAA', 
        headerStyle: {
          backgroundColor: '#121212',
        },
        headerTintColor: '#FFFFFF',
        headerRight: () => (
          <Pressable
           onPress={logout} 
           style={{ marginRight: 15 }}
           >
            <FontAwesome
              name="sign-out"
              size={24}
              color="#FFFFFF" 
            />
          </Pressable>
        ),
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: 'Home',
          tabBarIcon: ({ focused }) => (
            <FontAwesome 
              name="home" 
              size={24} 
              color={focused ? '#FFFFFF' : '#AAAAAA'} 
            />
          ),
        }}
      />
      <Tabs.Screen
        name="eligibility"
        options={{
          title: 'Check Eligibility',
          tabBarIcon: ({ focused }) => (
            <FontAwesome 
              name="check-circle" 
              size={24} 
              color={focused ? '#AAAAAA' : '#AAAAAA'} 
            />
          ),
        }}
      />
      <Tabs.Screen
        name="PollingStationsScreen"
        options={{
          title: 'Polling Stations',
          tabBarIcon: ({ focused }) => (
            <FontAwesome 
              name="map-marker" 
              size={24} 
              color={focused ? '#FFFFFF' : '#AAAAAA'} 
            />
          ),
        }}
      />
      <Tabs.Screen
        name="countyStats"
        options={{
          title: 'Statistics',
          tabBarIcon: ({ focused }) => (
            <FontAwesome 
              name="bar-chart" 
              size={24} 
              color={focused ? '#FFFFFF' : '#AAAAAA'} 
            />
          ),
        }}
      />
      <Tabs.Screen
        name="explore"
        options={{
          title: 'Explore',
          tabBarIcon: ({ focused }) => (
            <FontAwesome 
              name="info-circle" 
              size={24} 
              color={focused ? '#FFFFFF' : '#AAAAAA'} 
            />
          ),
        }}
      />
    </Tabs>
  );
}