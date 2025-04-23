import { createSlice } from "@reduxjs/toolkit";

// Load user data from localStorage on initialization
const storedUserData = localStorage.getItem("userData");
const initialUserData = storedUserData ? JSON.parse(storedUserData) : null;

const userSlice = createSlice({
  name: "user",
  initialState: {    
    data: initialUserData,
    loading: false,
    error: null,
  },
  reducers: {
    setUserData: (state, action) => {
      state.data = action.payload;
      // Save to localStorage
      localStorage.setItem("userData", JSON.stringify(state.data));
      state.loading = false;
    },
    setUserLoading: (state) => {
      state.loading = true;
    },
    setUserError: (state, action) => {
      state.error = action.payload;     
      state.loading = false;
      // Remove from localStorage if there's an error
      localStorage.removeItem("userData");
    },
    clearUserData: (state) => {
      state.data = null;
      state.loading = false;
      state.error = null;
       // Remove from localStorage 
      localStorage.removeItem("userData");
    },
  },
});

export const { setUserData, setUserLoading, setUserError, clearUserData } = userSlice.actions;
export default userSlice.reducer;
