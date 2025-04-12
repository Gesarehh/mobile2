import { DarkTheme, DefaultTheme, ThemeProvider } from '@react-navigation/native';
import { useFonts } from 'expo-font';
import { Stack as RouterStack } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';
import { useEffect } from 'react';
import 'react-native-reanimated';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { useColorScheme } from '@/hooks/useColorScheme';
import { AuthProvider } from '@/context/AuthContext';
// import { initDatabase } from '@/database/db';



const NativeStack = createNativeStackNavigator();


// function StationsStack() {
//   return (
//     <NativeStack.Navigator>
//       <NativeStack.Screen name="index" component={PollingStationsScreen} options={{ headerShown: false }} />
//       <NativeStack.Screen name="countyStats" component={CountyStatsScreen} options={{ title: 'County Details' }} />
//     </NativeStack.Navigator>
//   );
// }

SplashScreen.preventAutoHideAsync();

export default function RootLayout() {
  const colorScheme = useColorScheme();
  const [loaded] = useFonts({
    SpaceMono: require('../assets/fonts/SpaceMono-Regular.ttf'),
  });
  useEffect(() => {
    // initDataba/se();
  }, []) 

  useEffect(() => {
    if (loaded) {
      SplashScreen.hideAsync();
    }
  }, [loaded]);

  if (!loaded) {
    return null;
  }

  return (
    <ThemeProvider value={colorScheme === 'dark' ? DarkTheme : DefaultTheme}>
     <AuthProvider>
     <RouterStack>
        <RouterStack.Screen name="(tabs)" options={{ headerShown: false }} />
        <RouterStack.Screen name="login" options={{title: 'login'}} />
        <RouterStack.Screen name="signup" options={{title: 'signup'}} />
        <RouterStack.Screen name="+not-found" />
      </RouterStack>
      <StatusBar style="auto" />
      </AuthProvider>
     </ThemeProvider>
  );
}
