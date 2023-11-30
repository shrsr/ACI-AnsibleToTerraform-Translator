import styled from 'styled-components';

const AlertContainer = styled.div`
  background-color: #fff;
  border: 1px solid #ccc;
  border-radius: 4px;
  padding: 10px;
  margin-bottom: 10px;

  message {
    margin: 0;
  }
`;


const customAlert = ({ message }) => {
  return (
    <AlertContainer>
      <message>{message}</message>
    </AlertContainer>
  );
};

export default customAlert;
