import React from "react";

const HomePage: React.FC = () => {
  return (
    <div
      className="w-full h-screen bg-cover bg-center relative"
      style={{ backgroundImage: "url('/background.jpg')" }}
    >
      {/* Overlay Box */}
      <div
        className="
          absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2
          w-[90%] max-w-[900px] sm:h-[70%] h-[80%] flex flex-col sm:flex-row
          bg-black/40 shadow-lg backdrop-blur-sm rounded-3xl overflow-hidden
          sm:p-6 p-4 gap-4
        "
      >
        {/* Left Section */}
        <div className="flex-1 justify-center p-2">
          <p className="text-white text-center text-lg sm:text-xl">
            This is the left section with fully transparent background, so you
            can see the overlay shadow around it.
          </p>
        </div>

        {/* Right Section */}
        <div className="flex-1 sm:flex-2 flex items-center justify-center p-4">
          <div className="w-full h-full bg-black/50 shadow-lg backdrop-blur-sm rounded-lg p-6 flex flex-col items-center justify-center">
            <h1 className="text-white text-3xl font-bold">Welcome</h1>
            <p className="text-white mt-4 text-center">
              This is the right section with semi-transparent black overlay and
              shadow.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
