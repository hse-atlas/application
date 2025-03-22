import { createSlice } from "@reduxjs/toolkit";

const userSlice = createSlice({
  name: "user",
  initialState: {
    data: null,
    loading: false,
    error: null,
  },
  reducers: {
    setUserData: (state, action) => {
      state.data = action.payload;
      state.loading = false;
    },
    setUserLoading: (state) => {
      state.loading = true;
    },
    setUserError: (state, action) => {
      state.error = action.payload;
      state.loading = false;
    },
  },
});

export const { setUserData, setUserLoading, setUserError } = userSlice.actions;
export default userSlice.reducer;
